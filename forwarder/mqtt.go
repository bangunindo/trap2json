package forwarder

import (
	"crypto/tls"
	mqtt "github.com/eclipse/paho.mqtt.golang"
)

type TlsConfig struct {
	InsecureSkipVerify bool `mapstructure:"insecure_skip_verify"`
}

type MQTTConfig struct {
	Hosts    []string
	ClientID string `mapstructure:"client_id"`
	Username string
	Password string
	Ordered  *bool
	TLS      *TlsConfig
	Topic    string
	Qos      uint8
}

type MQTT struct {
	Base
}

func (m *MQTT) buildTLSConfig(c *mqtt.ClientOptions) {
	if m.config.MQTT.TLS != nil {
		tlsConf := &tls.Config{
			InsecureSkipVerify: m.config.MQTT.TLS.InsecureSkipVerify,
			ClientAuth:         tls.NoClientCert,
		}
		c.SetTLSConfig(tlsConf)
	}
}

func (m *MQTT) Run() {
	defer m.cancel()
	defer m.logger.Info().Msg("forwarder exited")
	m.logger.Info().Msg("starting forwarder")
	opts := mqtt.NewClientOptions().
		SetClientID(m.config.MQTT.ClientID).
		SetUsername(m.config.MQTT.Username).
		SetPassword(m.config.MQTT.Password).
		SetOrderMatters(*m.config.MQTT.Ordered)
	for _, server := range m.config.MQTT.Hosts {
		opts.AddBroker(server)
	}
	m.buildTLSConfig(opts)
	client := mqtt.NewClient(opts)
	token := client.Connect()
	token.Wait()
	defer client.Disconnect(10_000)
	for {
		msg, err := m.Get()
		if err != nil {
			break
		}
		msg.Compile(m.CompilerConf)
		if msg.Skip {
			m.ctrFiltered.Inc()
			continue
		}
		if t := client.Publish(m.config.MQTT.Topic, m.config.MQTT.Qos, false, msg.MessageJSON); t.Wait() &&
			t.Error() != nil {
			m.Retry(msg, t.Error())
		} else {
			m.ctrSucceeded.Inc()
		}
	}
}

func NewMQTT(c Config, idx int) Forwarder {
	fwd := &MQTT{
		NewBase(c, idx),
	}
	go fwd.Run()
	return fwd
}
