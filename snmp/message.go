package snmp

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type ValueType int8
type ValueDetail struct {
	Raw any     `json:"raw,omitempty" mapstructure:"raw"`
	Hex *string `json:"hex,omitempty" mapstructure:"hex"`
}

const (
	TypeUnknown ValueType = iota
	TypeInteger
	TypeDuration
	TypeEnum
	TypeIpAddress
	TypeOID
	TypeString
	TypeBytes
	TypeBits
	TypeDateAndTime
	TypeNull
)

var varTypeIntStr = map[ValueType]string{
	TypeUnknown:     "unknown",
	TypeInteger:     "integer",
	TypeDuration:    "duration",
	TypeEnum:        "enum",
	TypeIpAddress:   "ip_address",
	TypeOID:         "oid",
	TypeString:      "string",
	TypeBytes:       "bytes",
	TypeBits:        "bits",
	TypeDateAndTime: "datetime",
	TypeNull:        "null",
}
var varTypeSnmpInt = map[string]ValueType{
	"integer":    TypeInteger,
	"counter32":  TypeInteger,
	"counter64":  TypeInteger,
	"gauge32":    TypeInteger,
	"unsigned32": TypeInteger,
	"timeticks":  TypeDuration,
	"ipaddress":  TypeIpAddress,
	"oid":        TypeOID,
	"hex-string": TypeBytes,
	"string":     TypeString,
	"bits":       TypeBits,
	"null":       TypeNull,
}

func (v *ValueType) String() string {
	return varTypeIntStr[*v]
}

func (v *ValueType) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.String())
}

var durationPattern = regexp.MustCompile(`^\((\d+)\)`)
var enumPattern = regexp.MustCompile(`^(\w+)\((\d+)\)$`)

func (v *ValueType) parseEnum(text string) (any, ValueDetail, error) {
	if enumVar := enumPattern.FindStringSubmatch(text); len(enumVar) == 3 {
		// data is enum
		*v = TypeEnum
		if valInt, err := strconv.Atoi(enumVar[2]); err == nil {
			return enumVar[1], ValueDetail{Raw: valInt}, nil
		} else {
			log.Warn().Err(err).Msg("unexpected enum cast error")
			return enumVar[1], ValueDetail{}, nil
		}
	} else {
		if valInt, err := strconv.Atoi(text); err == nil {
			return valInt, ValueDetail{}, nil
		} else {
			return text, ValueDetail{}, errors.Wrapf(err, "failed casting to integer: %s", text)
		}
	}
}

func (v *ValueType) FromMIB(text string) error {
	switch text {
	case "DateAndTime":
		*v = TypeDateAndTime
		return nil
	}
	return errors.New("unknown mib type")
}

func (v *ValueType) FromSNMP(text string) error {
	text = strings.ToLower(text)
	if t, ok := varTypeSnmpInt[text]; !ok {
		return errors.Errorf("unknown snmp type: %s", text)
	} else {
		*v = t
	}
	return nil
}

func (v *ValueType) parseDateTime(text string) (any, ValueDetail, error) {
	dateTimeZoneParts := strings.Split(text, ",")
	if len(dateTimeZoneParts) < 2 {
		return text, ValueDetail{}, errors.New("not a valid DateAndTime")
	}
	timeZoneNormalized := "+00:00"
	if len(dateTimeZoneParts) == 3 {
		tz := dateTimeZoneParts[2]
		if (strings.HasPrefix(tz, "+") || strings.HasPrefix(tz, "-")) && strings.Count(tz, ":") == 1 {
			tzTrim := strings.TrimLeft(tz, "-+")
			tzSplit := strings.Split(tzTrim, ":")
			timeZoneNormalized = tz[:1] + fmt.Sprintf("%02s", tzSplit[0]) + ":" + fmt.Sprintf("%02s", tzSplit[1])
		}
	}
	dateTimeParts := strings.Join(append(dateTimeZoneParts[:2], timeZoneNormalized), ",")
	dateTime, err := time.Parse("2006-1-2,15:4:5.9,-07:00", dateTimeParts)
	if err == nil {
		return TimeJson{t: dateTime}, ValueDetail{Raw: text}, nil
	} else {
		return text, ValueDetail{}, errors.New("failed parsing DateAndTime")
	}
}

func (v *ValueType) Parse(text string) (any, ValueDetail, error) {
	switch *v {
	case TypeNull:
		return nil, ValueDetail{}, nil
	case TypeDateAndTime:
		return v.parseDateTime(text)
	case TypeDuration:
		if dur := durationPattern.FindStringSubmatch(text); len(dur) > 1 {
			if durInt, err := strconv.Atoi(dur[1]); err == nil {
				durSecs := float64(durInt) / 100
				durStr, _ := time.ParseDuration(fmt.Sprintf("%.2fs", durSecs))
				return durStr.String(), ValueDetail{Raw: float64(durInt) / 100}, nil
			} else {
				return text, ValueDetail{}, errors.Wrapf(err, "failed casting timeticks: %s", text)
			}
		} else {
			return text, ValueDetail{}, errors.Errorf("failed extracting timeticks: %s", text)
		}
	case TypeInteger:
		// TODO: decide what to do with integer DISPLAY-HINT
		return v.parseEnum(text)
	case TypeIpAddress:
		return text, ValueDetail{}, nil
	case TypeOID:
		mibName, _, err := translateOID(text)
		return mibName, ValueDetail{Raw: text}, err
	case TypeBytes:
		text = strings.ReplaceAll(text, " ", "")
		if s, err := hex.DecodeString(text); err != nil {
			return text, ValueDetail{}, errors.Wrapf(err, "failed casting hex: %s", text)
		} else if utf8.Valid(s) {
			*v = TypeString
			return string(s), ValueDetail{Hex: &text}, nil
		} else {
			return base64.StdEncoding.EncodeToString(s), ValueDetail{Hex: &text}, nil
		}
	case TypeString:
		// string DISPLAY-HINT is already handled in snmptrapd
		return text, ValueDetail{}, nil
	case TypeBits:
		text = strings.TrimSpace(text)
		textSplit := strings.Split(text, " ")
		hexVal := strings.Join(textSplit[:len(textSplit)-1], "")
		valRaw := textSplit[len(textSplit)-1]
		val, valDetail, err := v.parseEnum(valRaw)
		valDetail.Hex = &hexVal
		return val, valDetail, err
	default:
		return text, ValueDetail{}, errors.Errorf("unknown type: %s", v.String())
	}
}

type Value struct {
	OID         string      `json:"oid" mapstructure:"oid"`
	MIBName     string      `json:"mib_name" mapstructure:"mib_name"`
	Type        ValueType   `json:"type" mapstructure:"type"`
	NativeType  string      `json:"native_type" mapstructure:"native_type"`
	Value       any         `json:"value" mapstructure:"value"`
	ValueDetail ValueDetail `json:"value_detail" mapstructure:"value_detail"`
}

func (v Value) HasOIDPrefix(prefix string) bool {
	return v.OID == prefix ||
		v.MIBName == prefix ||
		strings.HasPrefix(v.OID, prefix+".") ||
		strings.HasPrefix(v.MIBName, prefix+".")
}

func (v Value) SnmpCmd() (cmd []string) {
	cmd = make([]string, 3)
	cmd[0] = v.OID
	switch v.NativeType {
	case "timeticks":
		cmd[1] = "t"
	case "integer":
		cmd[1] = "i"
	case "string", "hex-string":
		cmd[1] = "s"
	case "bits":
		cmd[1] = "b"
	case "counter32":
		cmd[1] = "c"
	case "gauge32", "unsigned32":
		cmd[1] = "u"
	case "ipaddress":
		cmd[1] = "a"
	case "oid":
		cmd[1] = "o"
	}
	switch v.Type {
	case TypeDuration:
		if val, ok := v.ValueDetail.Raw.(float64); ok {
			cmd[2] = fmt.Sprintf("%d", int(val*100))
		} else {
			cmd[2] = "0"
		}
	case TypeOID:
		cmd[2] = fmt.Sprintf("%v", v.ValueDetail.Raw)
	case TypeString, TypeInteger, TypeIpAddress:
		cmd[2] = fmt.Sprintf("%v", v.Value)
	case TypeDateAndTime:
		cmd[2] = fmt.Sprintf("%v", v.ValueDetail.Raw)
	case TypeEnum:
		if val, ok := v.ValueDetail.Raw.(int); ok {
			cmd[2] = fmt.Sprintf("%d", val)
		} else {
			cmd[2] = "0"
		}
	}
	return
}

const defaultTimeLayout = time.RFC3339Nano

type TimeJson struct {
	t      time.Time
	layout string
	tz     string
}

func (t *TimeJson) SetLayout(layout string) {
	t.layout = layout
}

func (t *TimeJson) SetTimezone(tz string) {
	t.tz = tz
}

func (t *TimeJson) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

func (t *TimeJson) String() string {
	var timeStr string
	switch t.layout {
	case "unix":
		timeStr = strconv.FormatInt(t.t.Unix(), 10)
	case "unixMilli":
		timeStr = strconv.FormatInt(t.t.UnixMilli(), 10)
	case "unixMicro":
		timeStr = strconv.FormatInt(t.t.UnixMicro(), 10)
	case "unixNano":
		timeStr = strconv.FormatInt(t.t.UnixNano(), 10)
	default:
		if t.layout == "" {
			t.layout = defaultTimeLayout
		}
		timeStr = t.t.Format(t.layout)
		if loc, err := time.LoadLocation(t.tz); err == nil && t.tz != "" {
			timeStr = t.t.In(loc).Format(t.layout)
		}
	}
	return timeStr
}

func (t *TimeJson) Time() time.Time {
	return t.t
}

func NewTimeJson(t time.Time) TimeJson {
	return TimeJson{
		t: t,
	}
}

type Message struct {
	LocalTime         *TimeJson `json:"time" mapstructure:"time"`
	UptimeSeconds     *float64  `json:"uptime_seconds" mapstructure:"uptime_seconds"`
	SourceAddress     *string   `json:"source_address" mapstructure:"source_address"`
	AgentAddress      *string   `json:"agent_address" mapstructure:"agent_address"`
	PDUVersion        *string   `json:"pdu_version" mapstructure:"pdu_version"`
	SNMPVersion       *string   `json:"snmp_version" mapstructure:"snmp_version"`
	Community         *string   `json:"community" mapstructure:"community"`
	EnterpriseOID     *string   `json:"enterprise_oid" mapstructure:"enterprise_oid"`
	EnterpriseMIBName *string   `json:"enterprise_mib_name" mapstructure:"enterprise_mib_name"`
	User              *string   `json:"user" mapstructure:"user"`
	Context           *string   `json:"context" mapstructure:"context"`
	Description       *string   `json:"description" mapstructure:"description"`
	TrapType          *int      `json:"trap_type" mapstructure:"trap_type"`
	TrapSubType       *int      `json:"trap_sub_type" mapstructure:"trap_sub_type"`
	Values            []Value   `json:"values" mapstructure:"values"`
}
