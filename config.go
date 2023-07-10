package main

import (
	"github.com/bangunindo/trap2json/forwarder"
	"github.com/bangunindo/trap2json/logger"
	"github.com/bangunindo/trap2json/metrics"
	"github.com/bangunindo/trap2json/snmp"
	"github.com/mitchellh/mapstructure"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/spf13/viper"
	"runtime"
)

type config struct {
	Logger       logger.Config
	SnmpTrapD    snmp.Config
	Forwarders   []forwarder.Config
	ParseWorkers int `mapstructure:"parse_workers"`
	Prometheus   metrics.Config
}

func parseConfig(path string) (config, error) {
	v := viper.New()
	v.SetDefault("logger.level", zerolog.InfoLevel)
	v.SetDefault("snmptrapd.listening", []string{"udp:10162", "udp6:10162"})
	v.SetDefault("parse_workers", runtime.NumCPU())
	v.SetDefault("prometheus.path", "/metrics")
	v.SetDefault("prometheus.port", 9285)
	v.SetDefault("snmptrapd.magic_begin", "--TFWDBEGIN--")
	v.SetDefault("snmptrapd.magic_end", "--TFWDEND--")
	v.SetConfigFile(path)
	err := v.ReadInConfig()
	if err != nil {
		return config{}, errors.Wrap(err, "failed reading config")
	}
	var c config
	err = v.Unmarshal(&c, viper.DecodeHook(mapstructure.TextUnmarshallerHookFunc()))
	if err != nil {
		return config{}, errors.Wrap(err, "failed unmarshalling configuration")
	}
	return c, nil
}
