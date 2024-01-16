package snmp

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/expr-lang/expr"
	"github.com/go-json-experiment/json"
	"github.com/pkg/errors"
	"reflect"
	"strconv"
)

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

func getOidValue(val []Value, oidPrefix string) any {
	for _, m := range val {
		if hasOIDPrefix(oidPrefix, m.OID, m.MIBName) {
			return m.Value
		}
	}
	return nil
}

var Functions = []expr.Option{
	expr.Function(
		"SHA256",
		func(params ...any) (any, error) {
			p, err := json.Marshal(params, json.Deterministic(true))
			if err != nil {
				return nil, err
			}
			h := sha256.New()
			h.Write(p)
			return hex.EncodeToString(h.Sum(nil)), nil
		},
		new(func(...any) string),
	),
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
			if val, ok := params[0].([]Value); !ok {
				return nil, errors.Errorf(
					"unexpected error, invalid first param type %s",
					reflect.TypeOf(params[0]),
				)
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
		new(func([]Value, string) any),
	),
	expr.Function(
		"OidValueNumber",
		func(params ...any) (any, error) {
			if val, ok := params[0].([]Value); !ok {
				return nil, errors.Errorf(
					"unexpected error, invalid first param type %s",
					reflect.TypeOf(params[0]),
				)
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
		new(func([]Value, string, bool) *float64),
	),
	expr.Function(
		"OidValueString",
		func(params ...any) (any, error) {
			if val, ok := params[0].([]Value); !ok {
				return nil, errors.Errorf(
					"unexpected error, invalid first param type %s",
					reflect.TypeOf(params[0]),
				)
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
		new(func([]Value, string, bool) *string),
	),
}
