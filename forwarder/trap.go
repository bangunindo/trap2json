package forwarder

import (
	"github.com/bangunindo/trap2json/snmp"
	"github.com/pkg/errors"
	"os/exec"
	"strconv"
	"sync"
)

type SNMPTrapConfig struct {
	Workers      int
	EnableInform bool `mapstructure:"enable_inform"`
	Host         string
	Version      string
	Community    string
	Context      string
	User         snmp.User
	// TODO support templating for these configs
}

type SNMPTrap struct {
	Base
	workerChan chan []string
	workerWg   *sync.WaitGroup
}

func (s *SNMPTrap) configCheck() error {
	if s.config.Trap.Host == "" {
		return errors.New("host is not defined")
	}
	switch s.config.Trap.Version {
	case "v1":
		if s.config.Trap.Community == "" {
			return errors.New("undefined community for snmp v1")
		}
		if s.config.Trap.EnableInform {
			s.logger.Warn().Msg("using inform in snmp v1 is not supported")
			s.config.Trap.EnableInform = false
		}
	case "v2c":
		if s.config.Trap.Community == "" {
			return errors.New("undefined community for snmp v2c")
		}
	case "v3":
		if s.config.Trap.User.Username == "" {
			return errors.New("undefined user for snmp v3")
		}
	default:
		return errors.Errorf("unknown snmp version: %s", s.config.Trap.Version)
	}
	return nil
}

func (s *SNMPTrap) baseBuilder() (cmd []string) {
	if s.config.Trap.EnableInform {
		cmd = append(cmd, "snmpinform")
	} else {
		cmd = append(cmd, "snmptrap")
	}
	cmd = append(cmd, "-"+s.config.Trap.Version)
	switch s.config.Trap.Version {
	case "v1", "v2c":
		cmd = append(cmd, "-c", s.config.Trap.Community)
	case "v3":
		cmd = append(cmd, "-l", s.config.Trap.User.SecurityLevel())
		cmd = append(cmd, "-u", s.config.Trap.User.Username)
		if s.config.Trap.User.AuthPassphrase != "" {
			cmd = append(cmd, "-a", s.config.Trap.User.AuthType.String())
			cmd = append(cmd, "-A", s.config.Trap.User.AuthPassphrase)
			if s.config.Trap.User.PrivacyPassphrase != "" {
				cmd = append(cmd, "-x", s.config.Trap.User.PrivacyProtocol.String())
				cmd = append(cmd, "-X", s.config.Trap.User.PrivacyPassphrase)
			}
		}
		if s.config.Trap.Context != "" {
			cmd = append(cmd, "-n", s.config.Trap.Context)
		}
		if s.config.Trap.User.EngineID != "" {
			cmd = append(cmd, "-e", s.config.Trap.User.EngineID)
		}
	default:
		s.logger.Warn().Msg("assertion error, unexpected snmp version")
	}
	cmd = append(cmd, s.config.Trap.Host)
	return
}

func (s *SNMPTrap) commandBuilder(baseCmd []string, m snmp.Message) (cmd []string) {
	cmd = baseCmd[:]
	values := m.Values[:]
	var uptime int
	if m.UptimeSeconds != nil {
		uptime = int(*m.UptimeSeconds * 100)
	}
	trapOid := ".1.3.6.1.6.3.1.1.4.1"
	if m.EnterpriseOID != nil {
		trapOid = *m.EnterpriseOID
	}
	switch s.config.Trap.Version {
	case "v1":
		var trapType, trapSubType int
		if m.TrapType != nil {
			trapType = *m.TrapType
		}
		if m.TrapSubType != nil {
			trapSubType = *m.TrapSubType
		}
		agentAddr := "0.0.0.0"
		if m.AgentAddress != nil {
			agentAddr = *m.AgentAddress
		}
		cmd = append(
			cmd,
			trapOid,
			agentAddr,
			strconv.Itoa(trapType),
			strconv.Itoa(trapSubType),
			strconv.Itoa(uptime),
		)
	case "v2c", "v3":
		cmd = append(cmd, strconv.Itoa(uptime), trapOid)
		if len(values) > 2 {
			// if it follows rfc, we remove the first two oids
			// remove sysuptime
			if values[0].OID == ".1.3.6.1.2.1.1.3.0" {
				values = values[1:]
			}
			// remove snmptrap oid
			if values[0].OID == ".1.3.6.1.6.3.1.1.4.1.0" {
				values = values[1:]
			}
		}
	default:
		s.logger.Warn().Msg("assertion error, unexpected snmp version")
		return
	}
	for _, val := range values {
		cmd = append(cmd, val.SnmpCmd()...)
	}
	return
}

func (s *SNMPTrap) runWorker() {
	defer s.workerWg.Done()
	for cmd := range s.workerChan {
		cmdOut := exec.Command(cmd[0], cmd[1:]...)
		if err := cmdOut.Run(); err != nil {
			s.logger.Warn().Err(err).Msg("failed sending trap")
			s.ctrDropped.Inc()
		} else {
			s.ctrSucceeded.Inc()
		}
	}
}

func (s *SNMPTrap) Run() {
	defer s.cancel()
	defer s.logger.Info().Msg("forwarder exited")
	s.logger.Info().Msg("starting forwarder")
	if err := s.configCheck(); err != nil {
		s.logger.Error().Err(err).Msg("failed starting trap forwarder")
		return
	}
	for i := 0; i < s.config.Trap.Workers; i++ {
		s.workerWg.Add(1)
		go s.runWorker()
	}
	baseCmd := s.baseBuilder()
	for m := range s.channel {
		_, _, skip := s.processMessage(m)
		if skip {
			continue
		}
		cmd := s.commandBuilder(baseCmd, m)
		s.workerChan <- cmd
	}
	close(s.workerChan)
	s.workerWg.Wait()
}

func NewSNMPTrap(c Config, idx int) Forwarder {
	fwd := &SNMPTrap{
		NewBase(c, idx),
		make(chan []string),
		new(sync.WaitGroup),
	}
	go fwd.Run()
	return fwd
}
