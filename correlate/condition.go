package correlate

import (
	"github.com/bangunindo/trap2json/snmp"
	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"github.com/pkg/errors"
	"reflect"
	"strings"
)

type Condition struct {
	Match      *vm.Program
	Identifier *vm.Program
	Clear      *vm.Program
}

func parseCondition(conf ConditionConfig) (*Condition, error) {
	var cond Condition
	var err error
	opts := []expr.Option{expr.Env(snmp.MessageCompiled{})}
	opts = append(opts, snmp.Functions...)
	boolOpts := append(opts, expr.AsBool())
	cond.Match, err = expr.Compile(conf.Match, boolOpts...)
	if err != nil {
		return nil, errors.Wrap(err, "match condition failed to compile")
	}
	cond.Clear, err = expr.Compile(conf.Clear, boolOpts...)
	if err != nil {
		return nil, errors.Wrap(err, "clear condition failed to compile")
	}
	stringOpts := append(opts, expr.AsKind(reflect.String))
	cond.Identifier, err = expr.Compile("SHA256("+strings.Join(conf.Identifiers, ",")+")", stringOpts...)
	if err != nil {
		return nil, errors.Wrap(err, "identifiers condition failed to compile")
	}
	return &cond, err
}
