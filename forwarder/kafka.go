package forwarder

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"github.com/bangunindo/trap2json/snmp"
	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"github.com/pkg/errors"
	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl/plain"
	"github.com/segmentio/kafka-go/sasl/scram"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

type KafkaSaslMechanism int

const (
	KafkaSaslPlain KafkaSaslMechanism = iota
	KafkaSaslSha256
	KafkaSaslSha512
)

func (k *KafkaSaslMechanism) String() string {
	switch *k {
	case KafkaSaslPlain:
		return "PLAIN"
	case KafkaSaslSha256:
		return "SCRAM-SHA-256"
	case KafkaSaslSha512:
		return "SCRAM-SHA-512"
	default:
		return ""
	}
}

func (k *KafkaSaslMechanism) UnmarshalText(text []byte) error {
	switch strings.ToLower(string(text)) {
	case "plain":
		*k = KafkaSaslPlain
	case "scram-sha-256":
		*k = KafkaSaslSha256
	case "scram-sha-512":
		*k = KafkaSaslSha512
	default:
		return errors.Errorf("unsupported KafkaSaslMechanism: %s", string(text))
	}
	return nil
}

type KafkaSasl struct {
	Username  string
	Password  string
	Mechanism KafkaSaslMechanism
}

type KafkaConfig struct {
	RequiredAcks kafka.RequiredAcks `mapstructure:"required_acks"`
	KeyField     string             `mapstructure:"key_field"`
	Hosts        []string
	Topic        string
	Tls          *Tls
	Sasl         *KafkaSasl
	BatchSize    int      `mapstructure:"batch_size"`
	BatchTimeout Duration `mapstructure:"batch_timeout"`
}

const kafkaMaxGoroutine = 10000

type Kafka struct {
	Base

	keyFieldTemplate *vm.Program
	wg               *sync.WaitGroup
	spawned          *atomic.Int32
}

func (k *Kafka) Run() {
	defer k.cancel()
	defer k.logger.Info().Msg("forwarder exited")
	k.logger.Info().Msg("starting forwarder")
	transport := kafka.DefaultTransport.(*kafka.Transport)
	if k.config.Kafka.Tls != nil {
		tlsConf := &tls.Config{
			InsecureSkipVerify: k.config.Kafka.Tls.InsecureSkipVerify,
		}
		if k.config.Kafka.Tls.CaCert != "" {
			ca, err := os.ReadFile(k.config.Kafka.Tls.CaCert)
			if err != nil {
				k.logger.Fatal().Err(err).Msg("failed reading ca certificate")
			}
			caCerts := x509.NewCertPool()
			caCerts.AppendCertsFromPEM(ca)
			tlsConf.RootCAs = caCerts
		}
		if k.config.Kafka.Tls.ClientCert != "" &&
			k.config.Kafka.Tls.ClientKey != "" {
			cert, err := tls.LoadX509KeyPair(k.config.Kafka.Tls.ClientCert, k.config.Kafka.Tls.ClientKey)
			if err != nil {
				k.logger.Fatal().Err(err).Msg("failed reading client certificate")
			}
			tlsConf.Certificates = []tls.Certificate{cert}
		}
		transport.TLS = tlsConf
	}
	if k.config.Kafka.Sasl != nil {
		switch k.config.Kafka.Sasl.Mechanism {
		case KafkaSaslPlain:
			transport.SASL = plain.Mechanism{
				Username: k.config.Kafka.Sasl.Username,
				Password: k.config.Kafka.Sasl.Password,
			}
		case KafkaSaslSha256, KafkaSaslSha512:
			var algo scram.Algorithm
			switch k.config.Kafka.Sasl.Mechanism {
			case KafkaSaslSha256:
				algo = scram.SHA256
			case KafkaSaslSha512:
				algo = scram.SHA512
			}
			sasl, err := scram.Mechanism(
				algo,
				k.config.Kafka.Sasl.Username,
				k.config.Kafka.Sasl.Password,
			)
			if err != nil {
				k.logger.Fatal().Err(err).Msg("failed preparing SASL authentication")
				return
			}
			transport.SASL = sasl
		}
	}
	producer := &kafka.Writer{
		Addr:         kafka.TCP(k.config.Kafka.Hosts...),
		Balancer:     kafka.Murmur2Balancer{},
		RequiredAcks: k.config.Kafka.RequiredAcks,
		Topic:        k.config.Kafka.Topic,
		BatchSize:    k.config.Kafka.BatchSize,
		BatchTimeout: k.config.Kafka.BatchTimeout.Duration,
		Transport:    transport,
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
		if k.spawned.Load() >= kafkaMaxGoroutine {
			k.wg.Wait()
		}
		k.wg.Add(1)
		k.spawned.Add(1)
		go func() {
			defer func() {
				k.spawned.Add(-1)
				k.wg.Done()
			}()
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
		}()
	}
}

func NewKafka(c Config, idx int) Forwarder {
	fwd := &Kafka{
		Base:    NewBase(c, idx),
		wg:      new(sync.WaitGroup),
		spawned: new(atomic.Int32),
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
