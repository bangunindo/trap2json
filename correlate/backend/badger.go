package backend

import (
	"encoding/json"
	"github.com/dgraph-io/badger/v4"
	"github.com/pkg/errors"
	"net/url"
	"time"
)

type badgerdb struct {
	ttl time.Duration
	db  *badger.DB
}

func (b *badgerdb) Pop(key string) (Data, bool, error) {
	var data Data
	err := b.db.Update(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(key))
		if err != nil {
			return errors.Wrap(err, "failed getting value")
		}
		raw, err := item.ValueCopy(nil)
		if err != nil {
			return errors.Wrap(err, "failed copying value")
		}
		err = json.Unmarshal(raw, &data)
		if err != nil {
			return errors.Wrap(err, "failed unmarshalling value")
		}
		err = txn.Delete([]byte(key))
		return errors.Wrap(err, "failed deleting value")
	})
	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			return Data{}, false, nil
		} else {
			return Data{}, false, err
		}
	}
	return data, true, nil
}

func (b *badgerdb) Set(key string, value Data) error {
	data, err := value.ToBytes()
	if err != nil {
		return err
	}
	err = b.db.Update(func(txn *badger.Txn) error {
		e := badger.NewEntry([]byte(key), data).WithTTL(b.ttl)
		return txn.SetEntry(e)
	})
	return errors.Wrap(err, "failed setting value")
}

func (b *badgerdb) Cleanup() error {
	// ttl is natively supported
	return nil
}

func (b *badgerdb) Close() error {
	return b.db.Close()
}

func newBadger(urlParsed *url.URL, ttl time.Duration) (Backend, error) {
	var opt badger.Options
	if urlParsed.Path == "" {
		opt = badger.DefaultOptions("").WithInMemory(true)
	} else {
		opt = badger.DefaultOptions(urlParsed.Path)
	}
	db, err := badger.Open(opt)
	if err != nil {
		return nil, errors.Wrap(err, "failed initiating badgerdb")
	}
	return &badgerdb{ttl: ttl, db: db}, nil
}
