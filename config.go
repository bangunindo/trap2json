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
	viper.SetDefault("logger.level", zerolog.InfoLevel)
	viper.SetDefault("snmptrapd.listening", []string{"udp:10162", "udp6:10162"})
	viper.SetDefault("parse_workers", runtime.NumCPU())
	viper.SetDefault("prometheus.path", "/metrics")
	viper.SetDefault("prometheus.port", 9285)
	viper.SetDefault("snmptrapd.magic_begin", "--TFWDBEGIN--")
	viper.SetDefault("snmptrapd.magic_end", "--TFWDEND--")
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(path)
	viper.AddConfigPath(".")
	_ = viper.ReadInConfig()
	var c config
	err := viper.Unmarshal(&c, viper.DecodeHook(mapstructure.TextUnmarshallerHookFunc()))
	if err != nil {
		return config{}, errors.Wrap(err, "failed unmarshalling configuration")
	}
	return c, nil
}
