package correlate

import (
	"github.com/bangunindo/trap2json/helper"
)

type Config struct {
	Enable           bool
	BackendURL       string `mapstructure:"backend_url"`
	TTL              helper.Duration
	Timeout          helper.Duration
	ShutdownWaitTime helper.Duration `mapstructure:"shutdown_wait_time"`
	QueueSize        int             `mapstructure:"queue_size"`
	Workers          int
	Conditions       []ConditionConfig
	AutoRetry        helper.AutoRetry `mapstructure:"auto_retry"`
}

type ConditionConfig struct {
	Match       string
	Identifiers []string
	Clear       string
}
