package forwarder

import (
	"context"
	"encoding/json"
	"github.com/Workiva/go-datastructures/queue"
	"github.com/bangunindo/trap2json/metrics"
	"github.com/bangunindo/trap2json/snmp"
	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"reflect"
	"strconv"
	"sync"
	"time"
)

type Duration struct {
	time.Duration
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

func (d *Duration) UnmarshalText(b []byte) error {
	if d == nil {
		return errors.New("can't unmarshal a nil *Duration")
	}
	var err error
	d.Duration, err = time.ParseDuration(string(b))
	return err
}

type AutoRetry struct {
	Enable     bool
	MaxRetries int      `mapstructure:"max_retries"`
	MinDelay   Duration `mapstructure:"min_delay"`
	MaxDelay   Duration `mapstructure:"max_delay"`
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
	TimeAsTimezone   string   `mapstructure:"time_as_timezone"`
	ShutdownWaitTime Duration `mapstructure:"shutdown_wait_time"`
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
	// Send will send the trap message to its corresponding forwarder.
	// Does nothing if the queue buffer is full or forwarder is already closed
	Send(message *snmp.Message)
	// Close informs the forwarder to stop processing any new messages
	Close()
	// Done informs the caller if forwarder is done processing
	Done() <-chan struct{}
}

type Base struct {
	idx             string
	fwdType         string
	config          Config
	queue           *queue.PriorityQueue
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

// Get returns error only if the queue is closed
func (b *Base) Get() (*snmp.Message, error) {
	var msg *snmp.Message
	for {
		if b.queue.Disposed() {
			return nil, queue.ErrDisposed
		}
		m := b.queue.Peek()
		if m == nil {
			time.Sleep(10 * time.Millisecond)
			continue
		} else {
			msg = m.(*snmp.Message)
			if msg.Eta.Before(time.Now()) {
				break
			} else {
				time.Sleep(10 * time.Millisecond)
				continue
			}
		}
	}
	if m, err := b.queue.Get(1); err == nil {
		msg = m[0].(*snmp.Message)
		return msg, nil
	} else {
		return nil, err
	}
}

// Send snmp message to forwarder
func (b *Base) Send(message *snmp.Message) {
	b.ctrProcessed.Inc()
	if b.config.QueueSize == 0 || b.queue.Len() < b.config.QueueSize {
		err := b.queue.Put(message)
		if err != nil {
			b.logger.Error().Msg("unexpected error, queue is closed")
			b.ctrDropped.Inc()
		}
	} else {
		b.logger.Warn().Msg("queue is full, consider increasing queue_size for this forwarder")
		b.ctrDropped.Inc()
	}
}

func (b *Base) Retry(message *snmp.Message, err error) {
	if b.config.AutoRetry.Enable && message.Retries < b.config.AutoRetry.MaxRetries {
		eta := message.ComputeEta(
			b.config.AutoRetry.MinDelay.Duration,
			b.config.AutoRetry.MaxDelay.Duration,
		)
		message.Retries++
		message.Eta = eta
		b.ctrRetried.Inc()
		b.logger.Debug().Err(err).Msg("retrying to forward trap")
		b.Send(message)
	} else {
		b.logger.Warn().Err(err).Msg("failed forwarding trap")
		b.ctrDropped.Inc()
	}
}

func (b *Base) Close() {
	go func() {
		if b.config.ShutdownWaitTime.Duration > 0 {
			timeout := time.After(b.config.ShutdownWaitTime.Duration)
		outer:
			for {
				select {
				case <-timeout:
					break outer
				default:
					if b.queue.Empty() {
						break outer
					}
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
		b.queue.Dispose()
	}()
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
		queue:   queue.NewPriorityQueue(c.QueueSize, true),
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
	var filterExpr, formatExpr *vm.Program
	var err error
	if c.Filter != "" {
		opts := []expr.Option{expr.AsBool(), expr.Env(snmp.MessageCompiled{})}
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
		opts := []expr.Option{expr.AsKind(reflect.Map), expr.Env(snmp.MessageCompiled{})}
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
		TimeFormat:     c.TimeFormat,
		TimeAsTimezone: c.TimeAsTimezone,
		Filter:         filterExpr,
		JSONFormat:     formatExpr,
		Logger:         base.logger,
	}
	// prometheus exporter for queue length
	go func() {
		base.ctrQueueCap.Set(float64(c.QueueSize))
		for {
			select {
			case <-time.After(time.Second):
				base.ctrQueueLen.Set(float64(base.queue.Len()))
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
			mCopy.Eta = time.Now()
			fwd.Send(&mCopy)
		}
	}
	for _, fwd := range forwarders {
		fwd.Close()
	}
	for _, fwd := range forwarders {
		<-fwd.Done()
	}
}
