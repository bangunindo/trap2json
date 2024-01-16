package helper

import (
	"github.com/go-json-experiment/json"
	"github.com/pkg/errors"
	"time"
)

type Duration struct {
	time.Duration
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

func (d *Duration) UnmarshalText(b []byte) error {
	if d == nil {
		return errors.New("can't unmarshal a nil *Duration")
	}
	var err error
	d.Duration, err = time.ParseDuration(string(b))
	return err
}

type AutoRetry struct {
	Enable     bool
	MaxRetries int      `mapstructure:"max_retries"`
	MinDelay   Duration `mapstructure:"min_delay"`
	MaxDelay   Duration `mapstructure:"max_delay"`
}
