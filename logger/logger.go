package logger

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"io"
	"strconv"
	"strings"
	"time"
)

type LogFormat int8

const (
	FormatConsole LogFormat = iota
	FormatJSON
)

//goland:noinspection GoMixedReceiverTypes
func (l LogFormat) String() string {
	switch l {
	case FormatConsole:
		return "console"
	case FormatJSON:
		return "json"
	}
	return strconv.Itoa(int(l))
}

//goland:noinspection GoMixedReceiverTypes
func (l *LogFormat) UnmarshalText(text []byte) error {
	if l == nil {
		return errors.New("can't unmarshal a nil *LogFormat")
	}
	switch string(text) {
	case "console":
		*l = FormatConsole
	case "json":
		*l = FormatJSON
	default:
		return errors.Errorf("unsupported LogFormat: %s", string(text))
	}
	return nil
}

//goland:noinspection GoMixedReceiverTypes
func (l LogFormat) MarshalText() ([]byte, error) {
	return []byte(l.String()), nil
}

type Config struct {
	Level  zerolog.Level
	Format LogFormat
}

func InitLogger(config Config, out io.Writer) {
	switch config.Format {
	case FormatConsole:
		output := zerolog.ConsoleWriter{
			Out:        out,
			NoColor:    true,
			TimeFormat: time.DateTime,
		}
		output.FormatLevel = func(i interface{}) string {
			return strings.ToUpper(fmt.Sprintf("| %-6s|", i))
		}
		log.Logger = zerolog.New(output).With().Timestamp().Logger()
	case FormatJSON:
		log.Logger = zerolog.New(out).With().Timestamp().Logger()
	}
	zerolog.SetGlobalLevel(config.Level)
}
