package helper

import (
	"encoding/json"
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
