package forwarder

import (
	"github.com/bangunindo/trap2json/helper"
	"github.com/bangunindo/trap2json/snmp"
	"github.com/pkg/errors"
	"time"
)

type MockConfig struct {
	OutChannel chan *snmp.Message
	Timeout    helper.Duration
}

type Mock struct {
	Base
}

func (m *Mock) Run() {
	defer m.cancel()
	defer m.logger.Info().Msg("forwarder exited")
	m.logger.Info().Msg("starting forwarder")

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
		if m.config.Mock.Timeout.Duration > 0 {
			select {
			case m.config.Mock.OutChannel <- msg:
				m.ctrSucceeded.Inc()
			case <-time.After(m.config.Mock.Timeout.Duration):
				m.Retry(msg, errors.New("timeout"))
			}
		} else {
			m.config.Mock.OutChannel <- msg
		}
	}
}

func NewMock(c Config, idx int) Forwarder {
	fwd := &Mock{
		NewBase(c, idx),
	}
	go fwd.Run()
	return fwd
}
