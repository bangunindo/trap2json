package helper

import (
	"fmt"
	"github.com/pkg/errors"
	"net/url"
	"strings"
)

func ParseDSN(DBUrl string) (string, string, error) {
	u, err := url.Parse(DBUrl)
	if err != nil {
		return "", "", err
	}
	switch u.Scheme {
	case "postgres":
		q := u.Query()
		q.Set("default_query_exec_mode", "simple_protocol")
		u.RawQuery = q.Encode()
		return "pgx", u.String(), nil
	case "mysql":
		q := u.Query()
		if v := q.Get("host"); v != "" {
			q.Del("host")
			u.RawQuery = q.Encode()
			u.Host = fmt.Sprintf("unix(%s)", v)
		} else {
			u.Host = fmt.Sprintf("tcp(%s)", u.Host)
		}
		dsn := strings.Replace(u.String(), "mysql://", "", 1)
		return "mysql", dsn, nil
	}
	return "", "", errors.Errorf("unsupported db backend: %s", u.Scheme)
}
