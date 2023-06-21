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
	if token := client.Connect(); token.Wait() && token.Error() != nil {
		m.logger.Warn().Err(token.Error()).Msg("failed connecting to mqtt broker")
		return
	}
	defer client.Disconnect(10_000)
	for msg := range m.channel {
		mJson, _, skip := m.processMessage(msg)
		if skip {
			continue
		}
		if t := client.Publish(m.config.MQTT.Topic, m.config.MQTT.Qos, false, mJson); t.Wait() &&
			t.Error() != nil {
			m.logger.Warn().Err(t.Error()).Msg("failed sending message to mqtt broker")
			m.ctrDropped.Inc()
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
