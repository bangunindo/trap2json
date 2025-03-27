package snmp

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/Workiva/go-datastructures/queue"
	"github.com/bangunindo/trap2json/helper"
	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"github.com/go-json-experiment/json"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type ValueType int8
type ValueDetail struct {
	Raw any    `json:"raw,omitempty" expr:"raw"`
	Hex string `json:"hex,omitempty" expr:"hex"`
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
	timeOffsetNormalized := "+00:00"
	if len(dateTimeZoneParts) == 3 {
		tz := dateTimeZoneParts[2]
		if (strings.HasPrefix(tz, "+") || strings.HasPrefix(tz, "-")) && strings.Count(tz, ":") == 1 {
			tzTrim := strings.TrimLeft(tz, "-+")
			tzSplit := strings.Split(tzTrim, ":")
			timeOffsetNormalized = tz[:1] + fmt.Sprintf("%02s", tzSplit[0]) + ":" + fmt.Sprintf("%02s", tzSplit[1])
		}
	}
	dateTimeParts := strings.Join(append(dateTimeZoneParts[:2], timeOffsetNormalized), ",")
	dateTime, err := time.Parse("2006-1-2,15:4:5.9,-07:00", dateTimeParts)
	if err == nil {
		return dateTime, ValueDetail{Raw: text}, nil
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
			return string(s), ValueDetail{Hex: text}, nil
		} else {
			return base64.StdEncoding.EncodeToString(s), ValueDetail{Hex: text}, nil
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
		valDetail.Hex = hexVal
		return val, valDetail, err
	default:
		return text, ValueDetail{}, errors.Errorf("unknown type: %s", v.String())
	}
}

type Value struct {
	OID         string      `json:"oid" expr:"oid"`
	MIBName     string      `json:"mib_name" expr:"mib_name"`
	Type        ValueType   `json:"type" expr:"type"`
	NativeType  string      `json:"native_type" expr:"native_type"`
	Value       any         `json:"value" expr:"value"`
	ValueDetail ValueDetail `json:"value_detail" expr:"value_detail"`
}

func hasOIDPrefix(prefix, oid, mibName string) bool {
	return oid == prefix ||
		mibName == prefix ||
		strings.HasPrefix(oid, prefix+".") ||
		strings.HasPrefix(mibName, prefix+".")
}

func (v Value) HasOIDPrefix(prefix string) bool {
	return hasOIDPrefix(prefix, v.OID, v.MIBName)
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

type MessageCompiler struct {
	Filter     *vm.Program
	JSONFormat *vm.Program
	Logger     zerolog.Logger
}

type Correlate struct {
	ID              string          `json:"id" expr:"id"`
	RaisedTime      time.Time       `json:"raised_time" expr:"raised_time"`
	Duration        helper.Duration `json:"duration" expr:"duration"`
	DurationSeconds float64         `json:"duration_seconds" expr:"duration_seconds"`
}

type Payload struct {
	Time              time.Time  `json:"time" expr:"time"`
	UptimeSeconds     *float64   `json:"uptime_seconds" expr:"uptime_seconds"`
	SrcAddress        string     `json:"src_address" expr:"src_address"`
	SrcPort           int        `json:"src_port" expr:"src_port"`
	DstAddress        string     `json:"dst_address" expr:"dst_address"`
	DstPort           int        `json:"dst_port" expr:"dst_port"`
	AgentAddress      *string    `json:"agent_address" expr:"agent_address"`
	PDUVersion        string     `json:"pdu_version" expr:"pdu_version"`
	SNMPVersion       string     `json:"snmp_version" expr:"snmp_version"`
	Community         *string    `json:"community" expr:"community"`
	EnterpriseOID     *string    `json:"enterprise_oid" expr:"enterprise_oid"`
	EnterpriseMIBName *string    `json:"enterprise_mib_name" expr:"enterprise_mib_name"`
	User              *string    `json:"user" expr:"user"`
	Context           *string    `json:"context" expr:"context"`
	Description       *string    `json:"description" expr:"description"`
	TrapType          *int64     `json:"trap_type" expr:"trap_type"`
	TrapSubType       *int64     `json:"trap_sub_type" expr:"trap_sub_type"`
	Values            []Value    `json:"values" expr:"value_list"`
	Correlate         *Correlate `json:"correlate" expr:"correlate"`
}

type Metadata struct {
	Retries        int
	Skip           bool
	MessageJSON    []byte
	Eta            time.Time
	Compiled       bool
	TimeAsTimezone string
	TimeFormat     string
}

type Message struct {
	Payload  *Payload
	Metadata Metadata
}

func (m *Message) Eta() time.Time {
	return m.Metadata.Eta
}

// Copy is only a shallow copy, only the metadata is different between messages
func (m *Message) Copy() Message {
	var mCopy Message
	mCopy.Payload = m.Payload
	return mCopy
}

func (m *Message) Compile(conf MessageCompiler) {
	// message can already be compiled in case of retry
	if m.Metadata.Compiled {
		return
	}
	defer func() {
		m.Metadata.Compiled = true
	}()
	if conf.Filter != nil {
		if continu, err := expr.Run(conf.Filter, *m.Payload); err == nil {
			if continueBool, ok := continu.(bool); ok {
				m.Metadata.Skip = !continueBool
			} else {
				conf.Logger.Debug().Err(err).Msg("failed evaluating filter expression")
			}
		}
	}
	if m.Metadata.Skip {
		return
	}
	var payload []byte
	var err error
	if conf.JSONFormat != nil {
		var res any
		if res, err = expr.Run(conf.JSONFormat, *m.Payload); err == nil {
			payload, err = json.Marshal(res, json.WithMarshalers(
				helper.JSONTimeMarshaller(
					m.Metadata.TimeFormat,
					m.Metadata.TimeAsTimezone,
				),
			))
			if err != nil {
				conf.Logger.Warn().Err(err).Msg("unexpected error, failed marshalling json")
			}
		} else {
			// conf.JSONFormat is already validated at this stage
			conf.Logger.Warn().Err(err).Msg("unexpected error, failed evaluating json_format expression")
		}
	}
	if payload == nil {
		payload, err = json.Marshal(m.Payload, json.WithMarshalers(
			helper.JSONTimeMarshaller(
				m.Metadata.TimeFormat,
				m.Metadata.TimeAsTimezone,
			),
		))
		if err != nil {
			conf.Logger.Warn().Err(err).Msg("unexpected error, failed marshalling json")
		}
	}
	m.Metadata.MessageJSON = payload
	return
}

func (m *Message) ComputeEta(minDelay, maxDelay time.Duration) time.Time {
	retryPow := int(math.Pow(2, float64(m.Metadata.Retries)))
	delay := minDelay * time.Duration(retryPow)
	if delay > maxDelay {
		delay = maxDelay
	}
	return time.Now().Add(delay)
}

func (m *Message) Compare(other queue.Item) int {
	otherM := other.(*Message)
	if otherM.Eta().Equal(m.Eta()) {
		return 0
	} else if otherM.Eta().After(m.Eta()) {
		return -1
	} else {
		return 1
	}
}
