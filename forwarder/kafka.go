package forwarder

import (
	"context"
	"encoding/json"
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
	for m := range k.channel {
		mJson, mVal, skip := k.processMessage(m)
		if skip {
			continue
		}
		var key []byte
		if k.config.Kafka.KeyField != "" {
			if v, ok := mVal[k.config.Kafka.KeyField]; ok && v != nil {
				if vByte, err := json.Marshal(v); err == nil {
					key = vByte
				}
			}
		}
		if err := producer.WriteMessages(
			context.Background(),
			kafka.Message{
				Key:   key,
				Value: mJson,
			},
		); err != nil {
			k.logger.Warn().Err(err).Msg("failed sending messages to kafka")
			k.ctrDropped.Inc()
		} else {
			k.ctrSucceeded.Inc()
		}
	}
}

func NewKafka(c Config, idx int) Forwarder {
	fwd := &Kafka{
		NewBase(c, idx),
	}
	go fwd.Run()
	return fwd
}
