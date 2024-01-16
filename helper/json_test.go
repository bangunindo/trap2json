package helper

import (
	"github.com/go-json-experiment/json"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestJSONTimeMarshaller(t *testing.T) {
	loc, err := time.LoadLocation("Asia/Jakarta")
	if assert.NoError(t, err) {
		s := struct {
			A int       `json:"a"`
			B float64   `json:"b"`
			C time.Time `json:"c"`
		}{
			A: 1,
			B: 1.1,
			C: time.Date(2020, 1, 1, 0, 0, 0, 101010101, loc),
		}
		data, err := json.Marshal(s,
			json.WithMarshalers(json.NewMarshalers(
				JSONTimeMarshaller(time.RFC3339, ""),
			)),
			json.Deterministic(true),
		)
		if assert.NoError(t, err) {
			assert.Equal(t, `{"a":1,"b":1.1,"c":"2020-01-01T00:00:00+07:00"}`, string(data))
		}
		data, err = json.Marshal(s,
			json.WithMarshalers(json.NewMarshalers(
				JSONTimeMarshaller(time.RFC3339, "Asia/Singapore"),
			)),
			json.Deterministic(true),
		)
		if assert.NoError(t, err) {
			assert.Equal(t, `{"a":1,"b":1.1,"c":"2020-01-01T01:00:00+08:00"}`, string(data))
		}
		data, err = json.Marshal(s,
			json.WithMarshalers(json.NewMarshalers(
				JSONTimeMarshaller("", ""),
			)),
			json.Deterministic(true),
		)
		if assert.NoError(t, err) {
			assert.Equal(t, `{"a":1,"b":1.1,"c":"2020-01-01T00:00:00.101010101+07:00"}`, string(data))
		}
		data, err = json.Marshal(s,
			json.WithMarshalers(json.NewMarshalers(
				JSONTimeMarshaller("unix", ""),
			)),
			json.Deterministic(true),
		)
		if assert.NoError(t, err) {
			assert.Equal(t, `{"a":1,"b":1.1,"c":1577811600}`, string(data))
		}
		data, err = json.Marshal(s,
			json.WithMarshalers(json.NewMarshalers(
				JSONTimeMarshaller("unixMilli", ""),
			)),
			json.Deterministic(true),
		)
		if assert.NoError(t, err) {
			assert.Equal(t, `{"a":1,"b":1.1,"c":1577811600101}`, string(data))
		}
		data, err = json.Marshal(s,
			json.WithMarshalers(json.NewMarshalers(
				JSONTimeMarshaller("unixMicro", ""),
			)),
			json.Deterministic(true),
		)
		if assert.NoError(t, err) {
			assert.Equal(t, `{"a":1,"b":1.1,"c":1577811600101010}`, string(data))
		}
		data, err = json.Marshal(s,
			json.WithMarshalers(json.NewMarshalers(
				JSONTimeMarshaller("unixNano", ""),
			)),
			json.Deterministic(true),
		)
		if assert.NoError(t, err) {
			assert.Equal(t, `{"a":1,"b":1.1,"c":1577811600101010101}`, string(data))
		}
	}
}
