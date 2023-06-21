package logger

import (
	"bufio"
	"bytes"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestLogFormat_UnmarshalText(t *testing.T) {
	var l2 *LogFormat
	err := l2.UnmarshalText([]byte("json"))
	assert.Error(t, err)
	var l3 LogFormat
	err = l3.UnmarshalText([]byte("json"))
	assert.NoError(t, err)
	assert.Equal(t, FormatJSON, l3)
	err = l3.UnmarshalText([]byte("console"))
	assert.NoError(t, err)
	assert.Equal(t, FormatConsole, l3)
	err = l3.UnmarshalText([]byte("should_error"))
	assert.Error(t, err)
}

func TestInitLogger(t *testing.T) {
	b := new(bytes.Buffer)
	out := bufio.NewWriter(b)
	InitLogger(
		Config{
			Level:  zerolog.InfoLevel,
			Format: FormatConsole,
		},
		out,
	)
	log.Info().Msg("testtest")
	err := out.Flush()
	assert.NoError(t, err)
	assert.Contains(t, b.String(), "| INFO  | testtest")
	b = new(bytes.Buffer)
	out = bufio.NewWriter(b)
	InitLogger(
		Config{
			Level:  zerolog.InfoLevel,
			Format: FormatJSON,
		},
		out,
	)
	log.Info().Msg("testtest")
	err = out.Flush()
	assert.NoError(t, err)
	assert.Contains(t, b.String(), `"message":"testtest"`)
	assert.Contains(t, b.String(), `"level":"info"`)
	assert.Contains(t, b.String(), `"time":"`)
}

func TestLogFormat_MarshalText(t *testing.T) {
	l1 := FormatConsole
	text, err := l1.MarshalText()
	assert.NoError(t, err)
	assert.Equal(t, []byte("console"), text)
	l1 = FormatJSON
	text, err = l1.MarshalText()
	assert.NoError(t, err)
	assert.Equal(t, []byte("json"), text)
	l1 = 8
	text, err = l1.MarshalText()
	assert.NoError(t, err)
	assert.Equal(t, []byte("8"), text)
}
