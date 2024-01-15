package helper

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestParseDSN(t *testing.T) {
	driver, dsn, err := ParseDSN("postgres://localhost")
	assert.NoError(t, err)
	assert.Equal(t, "pgx", driver)
	assert.Equal(t, "postgres://localhost?default_query_exec_mode=simple_protocol", dsn)
	driver, dsn, err = ParseDSN("mysql://localhost")
	assert.NoError(t, err)
	assert.Equal(t, "mysql", driver)
	assert.Equal(t, "tcp(localhost)", dsn)
}
