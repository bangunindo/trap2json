package snmp

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/Workiva/go-datastructures/queue"
	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gopkg.in/guregu/null.v4"
	"math"
	"reflect"
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
		return TimeLayout{Time: dateTime}, ValueDetail{Raw: text}, nil
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

type ValueCompiled struct {
	OID         string      `expr:"oid"`
	MIBName     string      `expr:"mib_name"`
	Type        string      `expr:"type"`
	NativeType  string      `expr:"native_type"`
	Value       any         `expr:"value"`
	ValueDetail ValueDetail `expr:"value_detail"`
}

type Value struct {
	OID         string      `json:"oid"`
	MIBName     null.String `json:"mib_name"`
	Type        ValueType   `json:"type"`
	NativeType  string      `json:"native_type"`
	Value       any         `json:"value"`
	ValueDetail ValueDetail `json:"value_detail"`
}

func (v Value) Compile(conf MessageCompiler) ValueCompiled {
	var newV any
	if t, ok := v.Value.(TimeLayout); ok {
		t.SetTimezone(conf.TimeAsTimezone)
		t.SetLayout(conf.TimeFormat)
		newV = t.MarshalNative()
	} else {
		newV = v.Value
	}
	return ValueCompiled{
		OID:         v.OID,
		MIBName:     v.MIBName.String,
		Type:        v.Type.String(),
		NativeType:  v.NativeType,
		Value:       newV,
		ValueDetail: v.ValueDetail,
	}
}

func hasOIDPrefix(prefix, oid, mibName string) bool {
	return oid == prefix ||
		mibName == prefix ||
		strings.HasPrefix(oid, prefix+".") ||
		strings.HasPrefix(mibName, prefix+".")
}

func (v Value) HasOIDPrefix(prefix string) bool {
	return hasOIDPrefix(prefix, v.OID, v.MIBName.String)
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

type TimeLayout struct {
	time.Time
	layout string
	tz     string
}

func (t *TimeLayout) SetLayout(layout string) {
	t.layout = layout
}

func (t *TimeLayout) SetTimezone(tz string) {
	t.tz = tz
}

func (t *TimeLayout) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.MarshalNative())
}

func (t *TimeLayout) MarshalNative() any {
	switch t.layout {
	case "unix":
		return t.Time.Unix()
	case "unixMilli":
		return t.Time.UnixMilli()
	case "unixMicro":
		return t.Time.UnixMicro()
	case "unixNano":
		return t.Time.UnixNano()
	}
	if t.layout == "" {
		t.layout = defaultTimeLayout
	}
	timeStr := t.Time.Format(t.layout)
	if loc, err := time.LoadLocation(t.tz); err == nil && t.tz != "" {
		timeStr = t.Time.In(loc).Format(t.layout)
	}
	return timeStr
}

func (t *TimeLayout) String() string {
	switch v := t.MarshalNative().(type) {
	case int64:
		return strconv.FormatInt(v, 10)
	case string:
		return v
	default:
		return fmt.Sprint(v)
	}
}

type MessageCompiler struct {
	TimeFormat     string
	TimeAsTimezone string
	Filter         *vm.Program
	JSONFormat     *vm.Program
	Logger         zerolog.Logger
}

type MessageCompiled struct {
	Time              any             `expr:"time"`
	UptimeSeconds     *float64        `expr:"uptime_seconds"`
	SrcAddress        string          `expr:"src_address"`
	SrcPort           int             `expr:"src_port"`
	DstAddress        string          `expr:"dst_address"`
	DstPort           int             `expr:"dst_port"`
	AgentAddress      *string         `expr:"agent_address"`
	PDUVersion        string          `expr:"pdu_version"`
	SNMPVersion       string          `expr:"snmp_version"`
	Community         *string         `expr:"community"`
	EnterpriseOID     *string         `expr:"enterprise_oid"`
	EnterpriseMIBName *string         `expr:"enterprise_mib_name"`
	User              *string         `expr:"user"`
	Context           *string         `expr:"context"`
	Description       *string         `expr:"description"`
	TrapType          *int64          `expr:"trap_type"`
	TrapSubType       *int64          `expr:"trap_sub_type"`
	Values            []ValueCompiled `expr:"values"`
}

func prepareValues(val any) ([]map[string]any, error) {
	switch vList := val.(type) {
	case []map[string]any:
		return vList, nil
	case []any:
		var res []map[string]any
		for _, m := range vList {
			if mCast, ok := m.(map[string]any); ok {
				res = append(res, mCast)
			} else {
				return nil, errors.Errorf("incorrect type passed %s", reflect.TypeOf(m))
			}
		}
		return res, nil
	case nil:
		return nil, nil
	default:
		return nil, errors.Errorf("incorrect type passed %s", reflect.TypeOf(val))
	}
}

func getOidValue(val []map[string]any, oidPrefix string) any {
	for _, m := range val {
		var oid, mibName string
		if oidAny, ok := m["oid"]; !ok {
			continue
		} else if oid, ok = oidAny.(string); !ok {
			continue
		}
		if mibNameAny, ok := m["mib_name"]; !ok {
			continue
		} else if mibName, ok = mibNameAny.(string); !ok {
			continue
		}
		if hasOIDPrefix(oidPrefix, oid, mibName) {
			return m["value"]
		}
	}
	return nil
}

var Functions = []expr.Option{
	expr.Function(
		"MergeMap",
		func(params ...any) (any, error) {
			if val, err := prepareValues(params[0]); err != nil {
				return nil, err
			} else {
				res := make(map[string]any)
				for _, m := range val {
					for k, v := range m {
						res[k] = v
					}
				}
				return res, nil
			}
		},
		new(func([]map[string]any) map[string]any),
	),
	expr.Function(
		"OidValueAny",
		func(params ...any) (any, error) {
			if val, err := prepareValues(params[0]); err != nil {
				return nil, err
			} else {
				prefix, ok := params[1].(string)
				if !ok {
					return nil, errors.Errorf(
						"unexpected error, invalid second param type %s",
						reflect.TypeOf(params[1]),
					)
				}
				valOid := getOidValue(val, prefix)
				return valOid, nil
			}
		},
		new(func([]map[string]any, string) any),
	),
	expr.Function(
		"OidValueNumber",
		func(params ...any) (any, error) {
			if val, err := prepareValues(params[0]); err != nil {
				return nil, err
			} else {
				prefix, ok := params[1].(string)
				if !ok {
					return nil, errors.Errorf(
						"unexpected error, invalid second param type %s",
						reflect.TypeOf(params[1]),
					)
				}
				tryCast, ok := params[2].(bool)
				if !ok {
					return nil, errors.Errorf(
						"unexpected error, invalid third param type %s",
						reflect.TypeOf(params[2]),
					)
				}
				valOid := getOidValue(val, prefix)
				switch v := valOid.(type) {
				case int:
					vFloat := float64(v)
					return &vFloat, nil
				case int8:
					vFloat := float64(v)
					return &vFloat, nil
				case int16:
					vFloat := float64(v)
					return &vFloat, nil
				case int32:
					vFloat := float64(v)
					return &vFloat, nil
				case int64:
					vFloat := float64(v)
					return &vFloat, nil
				case uint:
					vFloat := float64(v)
					return &vFloat, nil
				case uint8:
					vFloat := float64(v)
					return &vFloat, nil
				case uint16:
					vFloat := float64(v)
					return &vFloat, nil
				case uint32:
					vFloat := float64(v)
					return &vFloat, nil
				case uint64:
					vFloat := float64(v)
					return &vFloat, nil
				case float32:
					vFloat := float64(v)
					return &vFloat, nil
				case float64:
					return &v, nil
				case nil:
					return nil, nil
				default:
					if tryCast {
						if s, err := strconv.ParseFloat(fmt.Sprint(v), 64); err != nil {
							return nil, nil
						} else {
							return &s, nil
						}
					} else {
						return nil, nil
					}
				}
			}
		},
		new(func([]map[string]any, string, bool) *float64),
	),
	expr.Function(
		"OidValueString",
		func(params ...any) (any, error) {
			if val, err := prepareValues(params[0]); err != nil {
				return nil, err
			} else {
				prefix, ok := params[1].(string)
				if !ok {
					return nil, errors.Errorf(
						"unexpected error, invalid second param type %s",
						reflect.TypeOf(params[1]),
					)
				}
				tryCast, ok := params[2].(bool)
				if !ok {
					return nil, errors.Errorf(
						"unexpected error, invalid third param type %s",
						reflect.TypeOf(params[2]),
					)
				}
				valOid := getOidValue(val, prefix)
				switch v := valOid.(type) {
				case string:
					return &v, nil
				case nil:
					return nil, nil
				default:
					if tryCast {
						s := fmt.Sprint(v)
						return &s, nil
					} else {
						return nil, nil
					}
				}
			}
		},
		new(func([]map[string]any, string, bool) *string),
	),
}

type Message struct {
	Time              TimeLayout  `json:"time"`
	UptimeSeconds     null.Float  `json:"uptime_seconds"`
	SrcAddress        string      `json:"src_address"`
	SrcPort           int         `json:"src_port"`
	DstAddress        string      `json:"dst_address"`
	DstPort           int         `json:"dst_port"`
	AgentAddress      null.String `json:"agent_address"`
	PDUVersion        string      `json:"pdu_version"`
	SNMPVersion       string      `json:"snmp_version"`
	Community         null.String `json:"community"`
	EnterpriseOID     null.String `json:"enterprise_oid"`
	EnterpriseMIBName null.String `json:"enterprise_mib_name"`
	User              null.String `json:"user"`
	Context           null.String `json:"context"`
	Description       null.String `json:"description"`
	TrapType          null.Int    `json:"trap_type"`
	TrapSubType       null.Int    `json:"trap_sub_type"`
	Values            []Value     `json:"values"`

	Retries         int             `json:"-"`
	Eta             time.Time       `json:"-"`
	Skip            bool            `json:"-"`
	MessageCompiled MessageCompiled `json:"-"`
	MessageJSON     []byte          `json:"-"`
	compiled        bool
}

func (m *Message) Copy() Message {
	mValues := make([]Value, len(m.Values))
	copy(mValues, m.Values)
	mCopy := *m
	mCopy.Values = mValues
	return mCopy
}

func (m *Message) Compile(conf MessageCompiler) {
	// message can already be compiled in case of retry
	if m.compiled {
		return
	}
	defer func() {
		m.compiled = true
	}()
	m.Time.SetTimezone(conf.TimeAsTimezone)
	m.Time.SetLayout(conf.TimeFormat)
	var vc []ValueCompiled
	for _, v := range m.Values {
		vc = append(vc, v.Compile(conf))
	}
	m.MessageCompiled = MessageCompiled{
		Time:              m.Time.MarshalNative(),
		UptimeSeconds:     m.UptimeSeconds.Ptr(),
		SrcAddress:        m.SrcAddress,
		SrcPort:           m.SrcPort,
		DstAddress:        m.DstAddress,
		DstPort:           m.DstPort,
		AgentAddress:      m.AgentAddress.Ptr(),
		PDUVersion:        m.PDUVersion,
		SNMPVersion:       m.SNMPVersion,
		Community:         m.Community.Ptr(),
		EnterpriseOID:     m.EnterpriseOID.Ptr(),
		EnterpriseMIBName: m.EnterpriseMIBName.Ptr(),
		User:              m.User.Ptr(),
		Context:           m.Context.Ptr(),
		Description:       m.Description.Ptr(),
		TrapType:          m.TrapType.Ptr(),
		TrapSubType:       m.TrapSubType.Ptr(),
		Values:            vc,
	}
	if conf.Filter != nil {
		if continu, err := expr.Run(conf.Filter, m.MessageCompiled); err == nil {
			if continueBool, ok := continu.(bool); ok {
				m.Skip = !continueBool
			} else {
				conf.Logger.Debug().Err(err).Msg("failed evaluating filter expression")
			}
		}
	}
	if m.Skip {
		return
	}
	var payload []byte
	var err error
	if conf.JSONFormat != nil {
		var res any
		if res, err = expr.Run(conf.JSONFormat, m.MessageCompiled); err == nil {
			payload, err = json.Marshal(res)
			if err != nil {
				conf.Logger.Warn().Err(err).Msg("unexpected error, failed marshalling json")
			}
		} else {
			conf.Logger.Debug().Err(err).Msg("failed evaluating json_format expression")
		}
	}
	if payload == nil {
		payload, err = json.Marshal(m)
		if err != nil {
			conf.Logger.Warn().Err(err).Msg("unexpected error, failed marshalling json")
		}
	}
	m.MessageJSON = payload
	return
}

func (m *Message) ComputeEta(minDelay, maxDelay time.Duration) time.Time {
	retryPow := int(math.Pow(2, float64(m.Retries)))
	delay := minDelay * time.Duration(retryPow)
	if delay > maxDelay {
		delay = maxDelay
	}
	return time.Now().Add(delay)
}

func (m *Message) Compare(other queue.Item) int {
	otherM := other.(*Message)
	if otherM.Eta.Equal(m.Eta) {
		return 0
	} else if otherM.Eta.After(m.Eta) {
		return -1
	} else {
		return 1
	}
}
