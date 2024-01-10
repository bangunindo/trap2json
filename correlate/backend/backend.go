package backend

import (
	"encoding/json"
	"github.com/pkg/errors"
	"net/url"
	"time"
)

type Data struct {
	RaisedTimeSeconds int64  `json:"rts" db:"rts"`
	RaisedTimeNanos   int64  `json:"rtn" db:"rtn"`
	ID                string `json:"id" db:"id"`
}

func (d Data) ToBytes() ([]byte, error) {
	data, err := json.Marshal(d)
	if err != nil {
		return nil, errors.Wrap(err, "failed marshalling data")
	}
	return data, nil
}

func (d Data) Time() time.Time {
	return time.Unix(d.RaisedTimeSeconds, d.RaisedTimeNanos)
}

type Backend interface {
	// Pop returns false if key doesn't exists
	Pop(key string) (Data, bool, error)
	Set(key string, value Data) error
	Cleanup() error
	Close() error
}

func NewBackend(backendUrl string, ttl, timeout time.Duration) (Backend, error) {
	urlParsed, err := url.Parse(backendUrl)
	if err != nil {
		return nil, errors.Wrap(err, "invalid url syntax")
	}
	switch urlParsed.Scheme {
	case "badger":
		return newBadger(urlParsed, ttl)
	case "redis":
		return newRedis(urlParsed, ttl, timeout)
	case "postgres", "mysql":
		return newSql(urlParsed, ttl, timeout)
	default:
		return nil, errors.Errorf("invalid backend scheme: %s", urlParsed.Scheme)
	}
}
