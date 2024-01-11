package backend

import (
	"context"
	"encoding/json"
	"github.com/pkg/errors"
	"github.com/redis/go-redis/v9"
	"net/url"
	"time"
)

type redisdb struct {
	db      *redis.Client
	ttl     time.Duration
	timeout time.Duration
}

func (r *redisdb) Pop(key string) (Data, bool, error) {
	var ctx context.Context
	var cancel context.CancelFunc
	if r.timeout > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), r.timeout)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}
	defer cancel()
	val, err := r.db.GetDel(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return Data{}, false, nil
		} else {
			return Data{}, false, errors.Wrap(err, "failed getting value")
		}
	}
	var data Data
	err = json.Unmarshal([]byte(val), &data)
	if err != nil {
		return Data{}, false, errors.Wrap(err, "failed unmarshalling value")
	}
	return data, true, nil
}

func (r *redisdb) Set(key string, value Data) error {
	data, err := value.ToBytes()
	if err != nil {
		return err
	}
	var ctx context.Context
	var cancel context.CancelFunc
	if r.timeout > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), r.timeout)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}
	defer cancel()
	_, err = r.db.Set(ctx, key, data, r.ttl).Result()
	return errors.Wrap(err, "failed setting value")
}

func (r *redisdb) Cleanup() error {
	// ttl is natively supported
	return nil
}

func (r *redisdb) Close() error {
	return r.db.Close()
}

func newRedis(urlParsed *url.URL, ttl, timeout time.Duration) (Backend, error) {
	urlStr := urlParsed.String()
	opts, err := redis.ParseURL(urlStr)
	if err != nil {
		return nil, errors.Wrap(err, "failed initiating redis client")
	}
	return &redisdb{
		db:      redis.NewClient(opts),
		ttl:     ttl,
		timeout: timeout,
	}, nil
}
