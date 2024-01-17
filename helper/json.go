package helper

import (
	"github.com/go-json-experiment/json"
	"time"
)

const defaultTimeLayout = time.RFC3339Nano

func JSONTimeMarshaller(layout, tz string) *json.Marshalers {
	return json.MarshalFuncV1(
		func(t time.Time) ([]byte, error) {
			switch layout {
			case "unix":
				return json.Marshal(t.Unix())
			case "unixMilli":
				return json.Marshal(t.UnixMilli())
			case "unixMicro":
				return json.Marshal(t.UnixMicro())
			case "unixNano":
				return json.Marshal(t.UnixNano())
			}
			if layout == "" {
				layout = defaultTimeLayout
			}
			if loc, err := time.LoadLocation(tz); tz != "" && err == nil {
				return json.Marshal(t.In(loc).Format(layout))
			} else {
				return json.Marshal(t.Format(layout))
			}
		},
	)
}
