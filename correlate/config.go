package correlate

import (
	"github.com/bangunindo/trap2json/helper"
)

type Config struct {
	Enable     bool
	BackendURL string `mapstructure:"backend_url"`
	TTL        helper.Duration
	Timeout    helper.Duration
	QueueSize  int `mapstructure:"queue_size"`
	Workers    int
	Conditions []ConditionConfig
}

type ConditionConfig struct {
	Match       string
	Identifiers []string
	Clear       string
}
