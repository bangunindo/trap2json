package main

import (
	"github.com/bangunindo/trap2json/correlate"
	"github.com/bangunindo/trap2json/forwarder"
	"github.com/bangunindo/trap2json/helper"
	"github.com/bangunindo/trap2json/logger"
	"github.com/bangunindo/trap2json/metrics"
	"github.com/bangunindo/trap2json/snmp"
	"github.com/mitchellh/mapstructure"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/spf13/viper"
	"runtime"
	"time"
)

type config struct {
	Logger       logger.Config
	SnmpTrapD    snmp.Config
	Forwarders   []forwarder.Config
	ParseWorkers int `mapstructure:"parse_workers"`
	Prometheus   metrics.Config
	Correlate    correlate.Config
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
	v.SetDefault("snmptrapd.buffer_size", "64k")
	v.SetDefault("correlate.backend_url", "badger://")
	v.SetDefault("correlate.cleanup_interval", helper.Duration{Duration: time.Hour})
	v.SetDefault("correlate.ttl", helper.Duration{Duration: 30 * 24 * time.Hour})
	v.SetDefault("correlate.queue_size", 10000)
	v.SetDefault("correlate.workers", 4)
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
