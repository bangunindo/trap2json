package forwarder

import (
	"context"
	"encoding/json"
	"github.com/bangunindo/trap2json/metrics"
	"github.com/bangunindo/trap2json/snmp"
	"github.com/maja42/goval"
	"github.com/mitchellh/mapstructure"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/exp/maps"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Config struct {
	// ID identifies forwarder name, also used for prometheus labelling
	ID string
	// QueueSize defines the size of queue of each forwarder, when queue is full (might be caused
	// by slow forwarder) the message is dropped
	QueueSize uint `mapstructure:"queue_size"`
	// AgentAddressObjectPrefix populates Message.AgentAddress
	AgentAddressObjectPrefix string `mapstructure:"agent_address_object_prefix"`
	// TimeFormat specifies golang time format for casting time related fields to string
	TimeFormat string `mapstructure:"time_format"`
	// TimeAsTimezone will cast any time field to specified timezone
	TimeAsTimezone string `mapstructure:"time_as_timezone"`
	// Filter, JSONFormat, ValueJSONFormat utilizes maja42/goval expressions
	Filter          string
	JSONFormat      string `mapstructure:"json_format"`
	ValueJSONFormat string `mapstructure:"value_json_format"`
	ValueJSONIsFlat bool   `mapstructure:"value_json_is_flat"`
	File            *FileConfig
	Kafka           *KafkaConfig
	MQTT            *MQTTConfig
	Trap            *SNMPTrapConfig
	ZabbixTrapper   *ZabbixTrapperConfig `mapstructure:"zabbix_trapper"`
}

func (c *Config) Type() string {
	if c.File != nil {
		return "file"
	} else if c.Kafka != nil {
		return "kafka"
	} else if c.MQTT != nil {
		return "mqtt"
	} else if c.Trap != nil {
		return "trap"
	} else if c.ZabbixTrapper != nil {
		return "zabbix_trapper"
	} else {
		return "unknown"
	}
}

type Forwarder interface {
	// Send will send the trap message to its corresponding forwarder.
	// Does nothing if the queue buffer is full or forwarder is already closed
	Send(message snmp.Message)
	// Close informs the forwarder to stop processing any new messages
	Close()
	// Done informs the caller if forwarder is done processing
	Done() <-chan struct{}
}

var evalFunctions = map[string]goval.ExpressionFunction{
	// args: value field, regex pattern, message values
	"valueSelect": func(args ...any) (any, error) {
		if len(args) != 3 {
			return nil, errors.New("needs 3 arguments")
		}
		field, ok := args[0].(string)
		if !ok {
			return nil, errors.New("first argument should be string")
		}
		regexPattern, ok := args[1].(string)
		if !ok {
			return nil, errors.New("second argument should be string")
		}
		pattern, err := regexp.Compile(regexPattern)
		if err != nil {
			return nil, errors.Wrap(err, "invalid regex pattern on second argument")
		}
		values, ok := args[2].([]map[string]any)
		if !ok {
			return nil, errors.New("third argument should be list of values")
		}
		for _, val := range values {
			var valStr string
			if field == "type" {
				if s, ok := val[field].(snmp.ValueType); ok {
					valStr = s.String()
				}
			} else {
				if s, ok := val[field].(string); ok {
					valStr = s
				}
			}
			if valStr == "" {
				continue
			}
			if pattern.MatchString(valStr) {
				return val, nil
			}
		}
		emptyVal := map[string]any{}
		err = mapstructure.Decode(snmp.Value{}, &emptyVal)
		return emptyVal, err
	},
}

type Base struct {
	idx             string
	fwdType         string
	config          Config
	channel         chan snmp.Message
	ctx             context.Context
	cancel          context.CancelFunc
	ctrProcessed    prometheus.Counter
	ctrSucceeded    prometheus.Counter
	ctrDropped      prometheus.Counter
	ctrFiltered     prometheus.Counter
	ctrLookupFailed prometheus.Counter
	ctrQueueCap     prometheus.Gauge
	ctrQueueLen     prometheus.Gauge
	logger          zerolog.Logger
}

// Send snmp message to forwarder
// TODO: requeue message if the forwarder fails to send the messages
func (b *Base) Send(message snmp.Message) {
	select {
	case b.channel <- message:
	default:
		b.ctrDropped.Inc()
	}
}

func (b *Base) Close() {
	close(b.channel)
}

func (b *Base) Done() <-chan struct{} {
	return b.ctx.Done()
}

func (b *Base) filter(msgVars map[string]any) (bool, error) {
	if b.config.Filter == "" {
		return true, nil
	}
	eval := goval.NewEvaluator()
	if v, err := eval.Evaluate(b.config.Filter, msgVars, evalFunctions); err != nil {
		return false, errors.Wrap(err, "failed evaluating filters")
	} else if val, ok := v.(bool); !ok {
		return false, errors.New("return value is not boolean")
	} else {
		return val, nil
	}
}

func (b *Base) shouldContinue(m snmp.Message) (map[string]any, bool) {
	mVal := map[string]any{}
	var mValues []map[string]any
	err := mapstructure.Decode(m, &mVal)
	if err != nil {
		b.logger.Debug().Interface("message", m).Msgf("unexpected error, failed decoding mapstructure")
		b.ctrDropped.Inc()
		return nil, false
	} else {
		for k, v := range mVal {
			switch vcast := v.(type) {
			case *float64:
				if vcast != nil {
					mVal[k] = *vcast
				}
			case *string:
				if vcast != nil {
					mVal[k] = *vcast
				}
			case *int:
				if vcast != nil {
					mVal[k] = *vcast
				}
			}
		}
	}
	err = mapstructure.Decode(m.Values, &mValues)
	if err != nil {
		b.logger.Debug().Interface("values", m.Values).Msgf("unexpected error, failed decoding mapstructure")
		b.ctrDropped.Inc()
		return nil, false
	}
	mVal["values"] = mValues
	if passThrough, err := b.filter(mVal); err != nil {
		b.logger.Debug().Err(err).Interface("message", m).Msgf("filter expression failed")
	} else if !passThrough {
		b.ctrFiltered.Inc()
		return nil, false
	}
	if b.config.ValueJSONFormat != "" {
		eval := goval.NewEvaluator()
		if b.config.ValueJSONIsFlat {
			valuesFormattedFlat := map[string]any{}
			for _, v := range mValues {
				if vFmt, err := eval.Evaluate(b.config.ValueJSONFormat, v, evalFunctions); err != nil {
					b.logger.Debug().Err(err).Interface("value", v).Msgf("value format expression failed")
				} else if vCast, ok := vFmt.(map[string]any); ok {
					maps.Copy(valuesFormattedFlat, vCast)
				}
			}
			mVal["values_formatted"] = valuesFormattedFlat
		} else {
			var valuesFormattedList []any
			for _, v := range mValues {
				if vFmt, err := eval.Evaluate(b.config.ValueJSONFormat, v, evalFunctions); err != nil {
					b.logger.Debug().Err(err).Interface("value", v).Msgf("value format expression failed")
				} else {
					valuesFormattedList = append(valuesFormattedList, vFmt)
				}
			}
			mVal["values_formatted"] = valuesFormattedList
		}
	}
	return mVal, true
}

func (b *Base) processMessage(m snmp.Message) (mJson []byte, mVal map[string]any, skip bool) {
	var err error
	b.ctrProcessed.Inc()
	if m.LocalTime != nil {
		m.LocalTime.SetLayout(b.config.TimeFormat)
		m.LocalTime.SetTimezone(b.config.TimeAsTimezone)
	}
	prefix := strings.TrimRight(b.config.AgentAddressObjectPrefix, ".")
	for i, v := range m.Values {
		if b.config.AgentAddressObjectPrefix != "" && v.HasOIDPrefix(prefix) {
			if vStr, ok := v.Value.(string); ok {
				m.AgentAddress = &vStr
			}
		}
		if v.Type == snmp.TypeDateAndTime {
			if vTime, ok := v.Value.(snmp.TimeJson); ok {
				vTime.SetLayout(b.config.TimeFormat)
				vTime.SetTimezone(b.config.TimeAsTimezone)
				m.Values[i].Value = vTime.String()
			}
		}
	}
	// filter and json_format not defined, bypass any goval operations
	if b.config.Filter == "" &&
		b.config.JSONFormat == "" &&
		b.config.ValueJSONFormat == "" {
		mJson, err = json.Marshal(m)
	} else {
		var ok bool
		mVal, ok = b.shouldContinue(m)
		if !ok {
			skip = true
			return
		}
		if b.config.JSONFormat == "" {
			mJson, err = json.Marshal(m)
		} else {
			eval := goval.NewEvaluator()
			var v any
			v, err = eval.Evaluate(b.config.JSONFormat, mVal, evalFunctions)
			if err == nil {
				mJson, err = json.Marshal(v)
			}
		}
	}
	if err != nil {
		b.logger.Debug().Err(err).Msg("dropping message")
		b.ctrDropped.Inc()
		skip = true
	}
	return
}

func NewBase(c Config, idx int) Base {
	fwdType := c.Type()
	ctx, cancel := context.WithCancel(context.Background())
	idxStr := strconv.Itoa(idx + 1)
	base := Base{
		idx:     idxStr,
		fwdType: fwdType,
		config:  c,
		channel: make(chan snmp.Message, c.QueueSize),
		ctx:     ctx,
		cancel:  cancel,
		ctrProcessed: metrics.ForwarderProcessed.With(prometheus.Labels{
			"index": idxStr,
			"type":  fwdType,
			"id":    c.ID,
		}),
		ctrSucceeded: metrics.ForwarderSucceeded.With(prometheus.Labels{
			"index": idxStr,
			"type":  fwdType,
			"id":    c.ID,
		}),
		ctrDropped: metrics.ForwarderDropped.With(prometheus.Labels{
			"index": idxStr,
			"type":  fwdType,
			"id":    c.ID,
		}),
		ctrFiltered: metrics.ForwarderFiltered.With(prometheus.Labels{
			"index": idxStr,
			"type":  fwdType,
			"id":    c.ID,
		}),
		ctrLookupFailed: metrics.ForwarderLookupFailed.With(prometheus.Labels{
			"index": idxStr,
			"type":  fwdType,
			"id":    c.ID,
		}),
		ctrQueueCap: metrics.ForwarderQueueCapacity.With(prometheus.Labels{
			"index": idxStr,
			"type":  fwdType,
			"id":    c.ID,
		}),
		ctrQueueLen: metrics.ForwarderQueueFilled.With(prometheus.Labels{
			"index": idxStr,
			"type":  fwdType,
			"id":    c.ID,
		}),
		logger: log.
			With().
			Str("module", "forwarder").
			Str("index", idxStr).
			Str("type", fwdType).
			Str("id", c.ID).
			Logger(),
	}
	// prometheus exporter for queue length
	go func() {
		base.ctrQueueCap.Set(float64(cap(base.channel)))
		for {
			select {
			case <-time.After(time.Second):
				base.ctrQueueLen.Set(float64(len(base.channel)))
			case <-base.ctx.Done():
				return
			}
		}
	}()
	return base
}

func StartForwarders(wg *sync.WaitGroup, c []Config, messageChan <-chan snmp.Message) {
	defer wg.Done()
	var forwarders []Forwarder
	if len(c) == 0 {
		log.Warn().
			Str("module", "forwarder").
			Msg("no forwarders configured")
	}
	for i, fwd := range c {
		if fwd.QueueSize == 0 {
			fwd.QueueSize = 10000
		}
		switch fwd.Type() {
		case "file":
			forwarders = append(forwarders, NewFile(fwd, i))
		case "kafka":
			forwarders = append(forwarders, NewKafka(fwd, i))
		case "mqtt":
			if fwd.MQTT.Ordered == nil {
				b := true
				fwd.MQTT.Ordered = &b
			}
			forwarders = append(forwarders, NewMQTT(fwd, i))
		case "trap":
			if fwd.Trap.Workers == 0 {
				fwd.Trap.Workers = 1
			}
			forwarders = append(forwarders, NewSNMPTrap(fwd, i))
		case "zabbix_trapper":
			if fwd.ZabbixTrapper.Advanced != nil && fwd.ZabbixTrapper.Advanced.DBRefreshInterval.Duration == 0 {
				fwd.ZabbixTrapper.Advanced.DBRefreshInterval.Duration = 15 * time.Minute
			}
			if fwd.ZabbixTrapper.Advanced != nil && fwd.ZabbixTrapper.Advanced.DBQueryTimeout.Duration == 0 {
				fwd.ZabbixTrapper.Advanced.DBQueryTimeout.Duration = 5 * time.Second
			}
			forwarders = append(forwarders, NewZabbixTrapper(fwd, i))
		default:
			log.Warn().
				Str("module", "forwarder").
				Str("id", fwd.ID).
				Int("index", i+1).
				Msg("please define your forwarder destination")
		}
	}
	for msg := range messageChan {
		for _, fwd := range forwarders {
			fwd.Send(msg)
		}
	}
	for _, fwd := range forwarders {
		fwd.Close()
	}
	for _, fwd := range forwarders {
		<-fwd.Done()
	}
}
