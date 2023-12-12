package forwarder

import (
	"fmt"
	zsend "github.com/essentialkaos/go-zabbix"
	"github.com/pkg/errors"
	"net/url"
	"strings"
)

// ProxyConf is the list of available proxies in a zabbix system.
// In case of HA zabbix server, you need to include it here with its
// HANodeName
type ProxyConf struct {
	Hostname string
	Address  string
	Port     int
}

type ZSAdvancedConfig struct {
	Proxies  []ProxyConf
	proxyMap map[string]ProxyConf
	// for example:
	// - postgres://user:pass@127.0.0.1:5432/dbname?param1=value1&param2=value2
	// - mysql://user:pass@127.0.0.1:3306/dbname?param1=value1&param2=value2
	DBUrl             string   `mapstructure:"db_url"`
	DBRefreshInterval Duration `mapstructure:"db_refresh_interval"`
	DBQueryTimeout    Duration `mapstructure:"db_query_timeout"`
}

func (z *ZSAdvancedConfig) initProxyMap() {
	z.proxyMap = make(map[string]ProxyConf)
	for _, p := range z.Proxies {
		z.proxyMap[p.Hostname] = p
	}
}

func (z *ZSAdvancedConfig) getProxy(host string) (ProxyConf, bool) {
	h, ok := z.proxyMap[host]
	return h, ok
}

func (z *ZSAdvancedConfig) GetDSN() (string, string, error) {
	u, err := url.Parse(z.DBUrl)
	if err != nil {
		return "", "", err
	}
	switch u.Scheme {
	case "postgres":
		q := u.Query()
		q.Set("default_query_exec_mode", "simple_protocol")
		u.RawQuery = q.Encode()
		return "pgx", u.String(), nil
	case "mysql":
		q := u.Query()
		if v := q.Get("host"); v != "" {
			q.Del("host")
			u.RawQuery = q.Encode()
			u.Host = fmt.Sprintf("unix(%s)", v)
		} else {
			u.Host = fmt.Sprintf("tcp(%s)", u.Host)
		}
		dsn := strings.Replace(u.String(), "mysql://", "", 1)
		return "mysql", dsn, nil
	}
	return "", "", errors.Errorf("unsupported db backend: %s", u.Scheme)
}

type LookupStrategy int8

const (
	// LookupFromAgentAddress will use the agent address as hostname, or search for interface
	// ip/dns if db_url config is specified
	LookupFromAgentAddress LookupStrategy = iota
	// LookupFromSourceAddress will use the source address as hostname, or search for interface
	// ip/dns if db_url config is specified
	LookupFromSourceAddress
	// LookupFromOID will use the value of a given OID as the hostname. If db_url config is specified,
	// this will check for host existence before sending, and send it using default_hostname if it's not found
	LookupFromOID
)

func (l *LookupStrategy) String() string {
	switch *l {
	case LookupFromAgentAddress:
		return "agent_address"
	case LookupFromSourceAddress:
		return "source_address"
	case LookupFromOID:
		return "oid"
	default:
		return ""
	}
}

func (l *LookupStrategy) UnmarshalText(text []byte) error {
	switch strings.ToLower(string(text)) {
	case "agent_address":
		*l = LookupFromAgentAddress
	case "source_address":
		*l = LookupFromSourceAddress
	case "oid":
		*l = LookupFromOID
	default:
		return errors.Errorf("unsupported LookupStrategy: %s", string(text))
	}
	return nil
}

type ZabbixTrapperConfig struct {
	// default_* is used whenever host lookup fails:
	// - no advanced config defined
	// - proxy is defined in zabbix, but not defined in configuration
	// - can't find monitored hostname
	// - lookup strategy fails
	// DefaultAddress and DefaultPort are also used in case the host
	// is monitored directly with zabbix server and zabbix server
	// is not configured as HA
	DefaultAddress         string         `mapstructure:"default_address"`
	DefaultPort            int            `mapstructure:"default_port"`
	DefaultHostname        string         `mapstructure:"default_hostname"`
	ItemKey                string         `mapstructure:"item_key"`
	HostnameLookupStrategy LookupStrategy `mapstructure:"hostname_lookup_strategy"`
	OIDLookup              string         `mapstructure:"oid_lookup"`
	// Advanced config is for systems with proxies setup
	Advanced *ZSAdvancedConfig
}

type ZabbixTrapper struct {
	Base

	lookup *ZabbixLookup
}

func (z *ZabbixTrapper) Run() {
	defer z.cancel()
	defer z.logger.Info().Msg("forwarder exited")
	z.logger.Info().Msg("starting forwarder")
	for {
		m, err := z.Get()
		if err != nil {
			break
		}
		m.Compile(z.CompilerConf)
		if m.Skip {
			z.ctrFiltered.Inc()
			continue
		}
		address := fmt.Sprintf(
			"%s:%d",
			z.config.ZabbixTrapper.DefaultAddress,
			z.config.ZabbixTrapper.DefaultPort,
		)
		hostname := z.config.ZabbixTrapper.DefaultHostname
		if r, err := z.lookup.Lookup(m, z.config.ZabbixTrapper.HostnameLookupStrategy); err == nil {
			if r.Server != nil {
				address = fmt.Sprintf("%s:%d", r.Server.Address, r.Server.Port)
			}
			hostname = r.Hostname
		} else {
			z.ctrLookupFailed.Inc()
			z.logger.Debug().
				Interface("data", m).
				Msg("zabbix failed lookup")
		}
		if address == ":0" {
			z.ctrDropped.Inc()
			continue
		}
		c, err := zsend.NewClient(address, hostname)
		if err != nil {
			z.logger.Warn().Err(err).Msg("failed resolving address")
			z.ctrDropped.Inc()
			continue
		}
		item := c.Add(z.config.ZabbixTrapper.ItemKey, string(m.MessageJSON))
		item.Clock = m.Time.Unix()
		item.NS = m.Time.Nanosecond()
		z.logger.Trace().Str("address", address).Str("hostname", hostname).Msg("sending to zabbix")
		if _, err = c.Send(); err != nil {
			z.Retry(m, err)
		} else {
			z.ctrSucceeded.Inc()
		}
	}
}

func NewZabbixTrapper(c Config, idx int) Forwarder {
	b := NewBase(c, idx)
	fwd := &ZabbixTrapper{
		b,
		NewZabbixLookup(
			c.ZabbixTrapper,
			b.logger,
			b.ctx,
		),
	}
	go fwd.Run()
	return fwd
}
