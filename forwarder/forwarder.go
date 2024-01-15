package forwarder

import (
	"context"
	"github.com/bangunindo/trap2json/helper"
	"github.com/bangunindo/trap2json/metrics"
	"github.com/bangunindo/trap2json/queue"
	"github.com/bangunindo/trap2json/snmp"
	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"reflect"
	"strconv"
	"sync"
	"time"
)

type AutoRetry struct {
	Enable     bool
	MaxRetries int             `mapstructure:"max_retries"`
	MinDelay   helper.Duration `mapstructure:"min_delay"`
	MaxDelay   helper.Duration `mapstructure:"max_delay"`
}

type Config struct {
	// ID identifies forwarder name, also used for prometheus labelling
	ID string
	// QueueSize defines the size of queue of each forwarder, when queue is full (might be caused
	// by slow forwarder) the message is dropped
	QueueSize int `mapstructure:"queue_size"`
	// TimeFormat specifies golang time format for casting time related fields to string
	TimeFormat string `mapstructure:"time_format"`
	// TimeAsTimezone will cast any time field to specified timezone
	TimeAsTimezone   string          `mapstructure:"time_as_timezone"`
	ShutdownWaitTime helper.Duration `mapstructure:"shutdown_wait_time"`
	// Filter, JSONFormat utilizes antonmedv/expr expressions
	Filter        string
	JSONFormat    string    `mapstructure:"json_format"`
	AutoRetry     AutoRetry `mapstructure:"auto_retry"`
	Mock          *MockConfig
	File          *FileConfig
	Kafka         *KafkaConfig
	MQTT          *MQTTConfig
	Trap          *SNMPTrapConfig
	HTTP          *HTTPConfig
	ZabbixTrapper *ZabbixTrapperConfig `mapstructure:"zabbix_trapper"`
}

func (c *Config) Type() string {
	if c.File != nil {
		return "file"
	} else if c.Kafka != nil {
		return "kafka"
	} else if c.HTTP != nil {
		return "http"
	} else if c.MQTT != nil {
		return "mqtt"
	} else if c.Trap != nil {
		return "trap"
	} else if c.ZabbixTrapper != nil {
		return "zabbix_trapper"
	} else if c.Mock != nil {
		return "mock"
	} else {
		return "unknown"
	}
}

type Tls struct {
	InsecureSkipVerify bool   `mapstructure:"insecure_skip_verify"`
	CaCert             string `mapstructure:"ca_cert"`
	ClientCert         string `mapstructure:"client_cert"`
	ClientKey          string `mapstructure:"client_key"`
}

type Forwarder interface {
	// SendChannel will send the trap message to its corresponding forwarder.
	// Does nothing if the queue buffer is full or forwarder is already closed
	SendChannel() chan<- *snmp.Message
	// ReceiveChannel is used inside the forwarder to receive data
	// from SendChannel
	ReceiveChannel() <-chan *snmp.Message
	// Close informs the forwarder to stop processing any new messages
	Close()
	// Done informs the caller if forwarder is done processing
	Done() <-chan struct{}
	// Config returns the forwarder config
	Config() Config
}

type Base struct {
	idx             string
	fwdType         string
	config          Config
	queue           *queue.Queue[*snmp.Message]
	ctx             context.Context
	cancel          context.CancelFunc
	ctrProcessed    prometheus.Counter
	ctrSucceeded    prometheus.Counter
	ctrDropped      prometheus.Counter
	ctrRetried      prometheus.Counter
	ctrFiltered     prometheus.Counter
	ctrLookupFailed prometheus.Counter
	ctrQueueCap     prometheus.Gauge
	ctrQueueLen     prometheus.Gauge
	logger          zerolog.Logger
	CompilerConf    snmp.MessageCompiler
}

func (b *Base) Config() Config {
	return b.config
}

func (b *Base) SendChannel() chan<- *snmp.Message {
	return b.queue.SendChannel()
}

func (b *Base) ReceiveChannel() <-chan *snmp.Message {
	return b.queue.ReceiveChannel()
}

func (b *Base) Retry(message *snmp.Message, err error) {
	if b.config.AutoRetry.Enable && message.Metadata.Retries < b.config.AutoRetry.MaxRetries {
		eta := message.ComputeEta(
			b.config.AutoRetry.MinDelay.Duration,
			b.config.AutoRetry.MaxDelay.Duration,
		)
		message.Metadata.Retries++
		message.SetEta(eta)
		b.ctrRetried.Inc()
		b.logger.Debug().Err(err).Msg("retrying to forward trap")
		b.SendChannel() <- message
	} else {
		b.logger.Warn().Err(err).Msg("failed forwarding trap")
		b.ctrDropped.Inc()
	}
}

func (b *Base) Close() {
	b.queue.Close()
}

func (b *Base) Done() <-chan struct{} {
	return b.ctx.Done()
}

func NewBase(c Config, idx int) Base {
	fwdType := c.Type()
	ctx, cancel := context.WithCancel(context.Background())
	idxStr := strconv.Itoa(idx + 1)
	base := Base{
		idx:     idxStr,
		fwdType: fwdType,
		config:  c,
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
		ctrRetried: metrics.ForwarderRetried.With(prometheus.Labels{
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
	base.queue = queue.NewQueue[*snmp.Message](
		base.logger,
		c.QueueSize,
		c.ShutdownWaitTime.Duration,
		nil,
		queue.Counter{
			Processed: base.ctrProcessed,
			Drop:      base.ctrDropped,
			QueueCap:  base.ctrQueueCap,
			QueueLen:  base.ctrQueueLen,
		},
	)
	var filterExpr, formatExpr *vm.Program
	var err error
	if c.Filter != "" {
		opts := []expr.Option{expr.AsBool(), expr.Env(snmp.Payload{})}
		opts = append(opts, snmp.Functions...)
		filterExpr, err = expr.Compile(
			c.Filter,
			opts...,
		)
		if err != nil {
			base.logger.Fatal().Err(err).Msg("failed compiling filter expression")
		}
	}
	if c.JSONFormat != "" {
		opts := []expr.Option{expr.AsKind(reflect.Map), expr.Env(snmp.Payload{})}
		opts = append(opts, snmp.Functions...)
		formatExpr, err = expr.Compile(
			c.JSONFormat,
			opts...,
		)
		if err != nil {
			base.logger.Fatal().Err(err).Msg("failed compiling json_format expression")
		}
	}
	base.CompilerConf = snmp.MessageCompiler{
		Filter:     filterExpr,
		JSONFormat: formatExpr,
		Logger:     base.logger,
	}
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
		modLogger := log.With().
			Str("module", "forwarder").
			Str("id", fwd.ID).
			Int("index", i+1).
			Logger()
		if fwd.QueueSize == 0 {
			fwd.QueueSize = 10000
		}
		if fwd.QueueSize < 0 {
			fwd.QueueSize = 0
		}
		if fwd.AutoRetry.MaxRetries == 0 {
			fwd.AutoRetry.MaxRetries = 10
		}
		if fwd.AutoRetry.MinDelay.Duration == 0 {
			fwd.AutoRetry.MinDelay.Duration = time.Second
		}
		if fwd.AutoRetry.MaxDelay.Duration == 0 {
			fwd.AutoRetry.MaxDelay.Duration = time.Hour
		}
		if fwd.AutoRetry.MinDelay.Duration > fwd.AutoRetry.MaxDelay.Duration {
			if fwd.AutoRetry.Enable {
				modLogger.Warn().Msg("min_delay is larger than max_delay, will set max_delay the same as min_delay")
			}
			fwd.AutoRetry.MaxDelay = fwd.AutoRetry.MinDelay
		}
		if fwd.ShutdownWaitTime.Duration == 0 {
			fwd.ShutdownWaitTime.Duration = 5 * time.Second
		}
		switch fwd.Type() {
		case "mock":
			forwarders = append(forwarders, NewMock(fwd, i))
		case "file":
			forwarders = append(forwarders, NewFile(fwd, i))
		case "kafka":
			if fwd.Kafka.BatchSize == 0 {
				fwd.Kafka.BatchSize = 100
			}
			if fwd.Kafka.BatchTimeout.Duration == 0 {
				fwd.Kafka.BatchTimeout.Duration = time.Second
			}
			forwarders = append(forwarders, NewKafka(fwd, i))
		case "http":
			if fwd.HTTP.Timeout.Duration == 0 {
				fwd.HTTP.Timeout.Duration = 5 * time.Second
			}
			forwarders = append(forwarders, NewHTTP(fwd, i))
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
			modLogger.Warn().Msg("please define your forwarder destination")
		}
	}
	for msg := range messageChan {
		for _, fwd := range forwarders {
			mCopy := msg.Copy()
			mCopy.Metadata.TimeFormat = fwd.Config().TimeFormat
			mCopy.Metadata.TimeAsTimezone = fwd.Config().TimeAsTimezone
			mCopy.SetEta(time.Now())
			fwd.SendChannel() <- &mCopy
		}
	}
	for _, fwd := range forwarders {
		fwd.Close()
	}
	for _, fwd := range forwarders {
		<-fwd.Done()
	}
}
