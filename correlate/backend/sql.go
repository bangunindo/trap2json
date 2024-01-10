package backend

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/bangunindo/trap2json/helper"
	"github.com/georgysavva/scany/v2/sqlscan"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pkg/errors"
	"net/url"
	"time"
)

type sqldb struct {
	driver  string
	db      *sql.DB
	ttl     time.Duration
	timeout time.Duration
}

const sqlMigrationTimeout = 10 * time.Second

func (s *sqldb) migrate() error {
	ctx, cancel := context.WithTimeout(context.Background(), sqlMigrationTimeout)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.Wrap(err, "failed starting transaction")
	}
	var tableExists bool
	err = sqlscan.Get(
		ctx,
		tx,
		&tableExists,
		"select count(*) from information_schema.tables where table_name = 'trap2json_correlate'",
	)
	if err != nil {
		return errors.Wrap(err, "failed getting table information")
	}
	if !tableExists {
		_, err = tx.ExecContext(ctx, `
create table trap2json_correlate (
    key_ text   primary key,
    id   text   not null,
    rts  bigint not null,
    rtn  bigint not null
)
`)
		if err != nil {
			return errors.Wrap(err, "failed creating table")
		}
		_, err = tx.ExecContext(ctx, "create index rts_idx on trap2json_correlate(rts)")
		if err != nil {
			return errors.Wrap(err, "failed creating index")
		}
	}
	return errors.Wrap(tx.Commit(), "failed committing transaction")
}

func (s *sqldb) Pop(key string) (Data, bool, error) {
	//TODO implement me
	panic("implement me")
}

func (s *sqldb) Set(key string, value Data) error {
	//TODO implement me
	panic("implement me")
}

func (s *sqldb) Cleanup() error {
	var ctx context.Context
	var cancel context.CancelFunc
	if s.timeout > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), s.timeout)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.Wrap(err, "failed starting transaction")
	}
	olderThan := time.Now().Add(-s.ttl).Unix()
	switch s.driver {
	case "pgx":
		_, err = tx.ExecContext(ctx, "delete trap2json_correlate where rts < $1", olderThan)
	case "mysql":
		_, err = tx.ExecContext(ctx, "delete trap2json_correlate where rts < ?", olderThan)
	default:
		panic(fmt.Sprintf("unexpected driver found %s", s.driver))
	}
	if err != nil {
		return errors.Wrap(err, "failed cleanup")
	}
	return errors.Wrap(tx.Commit(), "failed committing transaction")
}

func (s *sqldb) Close() error {
	return s.db.Close()
}

func newSql(urlParsed *url.URL, ttl, timeout time.Duration) (Backend, error) {
	driver, dsn, err := helper.ParseDSN(urlParsed.String())
	if err != nil {
		return nil, err
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, errors.Wrap(err, "failed initializing db")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	err = db.PingContext(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed connecting to db")
	}
	instance := &sqldb{
		driver:  driver,
		db:      db,
		ttl:     ttl,
		timeout: timeout,
	}
	err = instance.migrate()
	if err != nil {
		return nil, err
	}
	return instance, nil
}
