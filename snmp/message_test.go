package snmp

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestValueType_Parse(t *testing.T) {
	vt := TypeDateAndTime
	loc, err := time.LoadLocation("Asia/Jakarta")
	assert.NoError(t, err)
	expectedTime := time.Date(2023, 12, 31, 3, 51, 9, 200_000_000, loc)
	val, _, err := vt.Parse("2023-12-31,3:51:9.2,+7:0")
	assert.NoError(t, err)
	valT, ok := val.(time.Time)
	assert.True(t, ok)
	assert.Equal(t, expectedTime, valT.In(loc))
	_, _, err = vt.Parse("2023-12-31")
	assert.Error(t, err)
	_, _, err = vt.Parse("2023-12-31,3:72:9.2,+7:0")
	assert.Error(t, err)

	vt = TypeDuration
	val, _, err = vt.Parse("(200) 00:00:02")
	assert.NoError(t, err)
	valS, ok := val.(string)
	assert.True(t, ok)
	assert.Equal(t, "2s", valS)
	_, _, err = vt.Parse("(x00) 00:00:02")
	assert.Error(t, err)

	vt = TypeInteger
	val, _, err = vt.Parse("200")
	assert.NoError(t, err)
	valI, ok := val.(int)
	assert.True(t, ok)
	assert.Equal(t, 200, valI)
	_, _, err = vt.Parse("xxx")
	assert.Error(t, err)
	val, _, err = vt.Parse("mantap(2)")
	assert.NoError(t, err)
	valS, ok = val.(string)
	assert.True(t, ok)
	assert.Equal(t, "mantap", valS)
	assert.Equal(t, TypeEnum, vt)

	vt = TypeIpAddress
	val, _, err = vt.Parse("10.0.0.1")
	assert.NoError(t, err)
	valS, ok = val.(string)
	assert.True(t, ok)
	assert.Equal(t, "10.0.0.1", valS)
}
