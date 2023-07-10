package forwarder

import (
	"context"
	"encoding/json"
	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"
	"github.com/bangunindo/trap2json/snmp"
	"github.com/segmentio/kafka-go"
)

type KafkaConfig struct {
	RequiredAcks kafka.RequiredAcks `mapstructure:"required_acks"`
	KeyField     string             `mapstructure:"key_field"`
	Hosts        []string
	Topic        string
}

type Kafka struct {
	Base

	keyFieldTemplate *vm.Program
}

func (k *Kafka) Run() {
	defer k.cancel()
	defer k.logger.Info().Msg("forwarder exited")
	k.logger.Info().Msg("starting forwarder")
	producer := &kafka.Writer{
		Addr:         kafka.TCP(k.config.Kafka.Hosts...),
		Balancer:     kafka.Murmur2Balancer{},
		RequiredAcks: k.config.Kafka.RequiredAcks,
		Topic:        k.config.Kafka.Topic,
		BatchSize:    1,
	}
	defer producer.Close()

	for {
		m, err := k.Get()
		if err != nil {
			break
		}
		m.Compile(k.CompilerConf)
		if m.Skip {
			k.ctrFiltered.Inc()
			continue
		}
		var key []byte
		if k.keyFieldTemplate != nil {
			if res, err := expr.Run(k.keyFieldTemplate, m.MessageCompiled); err == nil {
				switch v := res.(type) {
				case string:
					key = []byte(v)
				default:
					key, err = json.Marshal(v)
					if string(key) == "null" {
						key = nil
					}
				}
			}
		}
		if err := producer.WriteMessages(
			context.Background(),
			kafka.Message{
				Key:   key,
				Value: m.MessageJSON,
			},
		); err != nil {
			k.Retry(m, err)
		} else {
			k.ctrSucceeded.Inc()
		}
	}
}

func NewKafka(c Config, idx int) Forwarder {
	fwd := &Kafka{
		Base: NewBase(c, idx),
	}
	var err error
	if fwd.config.Kafka.KeyField != "" {
		fwd.keyFieldTemplate, err = expr.Compile(
			fwd.config.Kafka.KeyField,
			expr.Env(snmp.MessageCompiled{}),
		)
		if err != nil {
			fwd.logger.Fatal().Err(err).Msg("failed compiling kafka.key_field expression")
		}
	}
	go fwd.Run()
	return fwd
}
