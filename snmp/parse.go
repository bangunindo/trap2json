package snmp

import (
	"bytes"
	"encoding/csv"
	"github.com/bangunindo/trap2json/metrics"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog/log"
	"github.com/sleepinggenius2/gosmi"
	"github.com/sleepinggenius2/gosmi/types"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Header int8

const (
	HeaderAgentAddress Header = iota
	HeaderConnection
	HeaderTime
	HeaderUptime
	HeaderDescription
	HeaderEnterprise
	HeaderSecurity
	HeaderTrapType
	HeaderTrapSubType
	HeaderVarBinds
)

var connectionPattern = regexp.MustCompile(`\w+: \[([\w.-]+)]:([0-9]+)->\[([\w.-]+)]:([0-9]+)`)
var varBindPattern = regexp.MustCompile(`^([0-9.]+) = (.+): (.+)$`)
var varBindNullPattern = regexp.MustCompile(`^([0-9.]+) = ""$`)

const fieldsPerRecord = 10

func (m *Message) parseSecurityInfo(text string) {
	secParse := csv.NewReader(strings.NewReader(text))
	secParse.Comma = ','
	secParse.TrimLeadingSpace = true
	secParse.LazyQuotes = true
	if secInfo, err := secParse.Read(); err == nil && len(secInfo) > 2 {
		m.Payload.PDUVersion = secInfo[0]
		for _, sec := range secInfo[1:] {
			secSplit := strings.Split(sec, " ")
			if len(secSplit) < 2 || len(secSplit[0]) < 4 {
				continue
			}
			switch secSplit[0][:4] {
			case "SNMP":
				m.Payload.SNMPVersion = secSplit[1]
			case "user":
				m.Payload.User = &secSplit[1]
			case "cont":
				m.Payload.Context = &secSplit[1]
			case "comm":
				m.Payload.Community = &secSplit[1]
			}
		}
	}
}

func translateOID(oid string) (string, *gosmi.SmiNode, error) {
	oid = strings.TrimLeft(oid, ".")
	oidParsed, err := types.OidFromString(oid)
	if err != nil {
		return "", nil, err
	}
	node, err := gosmi.GetNodeByOID(oidParsed)
	if err != nil {
		return "", nil, err
	}
	oidName := node.RenderQualified()
	oidName = oidName + strings.Replace(oid, node.Oid.String(), "", 1)
	return oidName, &node, nil
}

const uptimeOID = ".1.3.6.1.2.1.1.3.0"
const agentOID = ".1.3.6.1.6.3.18.1.3"
const enterpriseOID = ".1.3.6.1.6.3.1.1.4.1.0"

func (m *Message) parseValues(text string) {
	varParse := csv.NewReader(strings.NewReader(text))
	varParse.Comma = '\t'
	varParse.TrimLeadingSpace = true
	varParse.LazyQuotes = true
	if varBinds, err := varParse.Read(); err == nil {
		for _, varBind := range varBinds {
			fields := varBindPattern.FindStringSubmatch(varBind)
			if len(fields) != 4 {
				if fields = varBindNullPattern.FindStringSubmatch(varBind); len(fields) == 2 {
					fields = []string{
						fields[0],
						fields[1],
						"NULL",
						"",
					}
				} else {
					log.Debug().Str("fields", varBind).Msg("value dropped, format unknown")
					continue
				}
			}
			fields = fields[1:]
			log.Trace().Strs("fields", fields).Msg("value matches")
			oidText := fields[0]
			valTypeText := fields[1]
			valueText := fields[2]
			var valType ValueType
			mibName, node, err := translateOID(oidText)
			value := Value{
				OID:        oidText,
				MIBName:    mibName,
				NativeType: strings.ToLower(valTypeText),
			}
			if node != nil && node.Type != nil {
				if err = valType.FromMIB(node.Type.Name); err != nil {
					_ = valType.FromSNMP(valTypeText)
				}
			} else {
				_ = valType.FromSNMP(valTypeText)
			}
			valueRaw, valueDetail, err := valType.Parse(valueText)
			if err != nil {
				log.Debug().Err(err).Strs("fields", fields).Msg("parsing surrender")
			}
			value.Type = valType
			value.Value = valueRaw
			value.ValueDetail = valueDetail
			if oidText == uptimeOID {
				if v, ok := valueDetail.Raw.(float64); ok {
					m.Payload.UptimeSeconds = &v
				}
			}
			if oidText == agentOID || strings.HasPrefix(oidText, agentOID+".") {
				if v, ok := valueRaw.(string); ok {
					m.Payload.AgentAddress = &v
				}
			}
			if oidText == enterpriseOID {
				if v, ok := valueDetail.Raw.(string); ok {
					m.Payload.EnterpriseOID = &v
				}
			}
			m.Payload.Values = append(m.Payload.Values, value)
		}
	}
	if m.Payload.EnterpriseOID != nil {
		if name, _, err := translateOID(*m.Payload.EnterpriseOID); err == nil {
			m.Payload.EnterpriseMIBName = &name
		}
	}
}

func (m *Message) UnmarshalText(text []byte) error {
	if m.Payload == nil {
		m.Payload = new(Payload)
	}
	// long snmptrapd messages sometimes have newline character in it
	text = bytes.Replace(text, []byte("\n"), []byte{}, -1)
	r := csv.NewReader(bytes.NewReader(text))
	r.Comma = '|'
	r.FieldsPerRecord = fieldsPerRecord
	r.LazyQuotes = true
	row, err := r.Read()
	if err != nil {
		return errors.Wrap(err, "failed parsing message")
	}
	if agentAddr := row[HeaderAgentAddress]; agentAddr != "0.0.0.0" && agentAddr != "" {
		m.Payload.AgentAddress = &agentAddr
	}
	if connection := connectionPattern.FindStringSubmatch(row[HeaderConnection]); len(connection) > 4 {
		m.Payload.SrcAddress = connection[1]
		if i, err := strconv.Atoi(connection[2]); err == nil {
			m.Payload.SrcPort = i
		}
		m.Payload.DstAddress = connection[3]
		if i, err := strconv.Atoi(connection[4]); err == nil {
			m.Payload.DstPort = i
		}
	}
	// we're using system generated time here instead of parsing from snmptrapd
	// because if trap message arrived at the same second mark, zabbix will reject
	// the message and get marked as duplicate
	m.Payload.Time = time.Now()
	if sysUptime, err := strconv.Atoi(row[HeaderUptime]); err == nil && sysUptime > 0 {
		uptime := float64(sysUptime) / 100
		m.Payload.UptimeSeconds = &uptime
	}
	if description := row[HeaderDescription]; description != "" {
		m.Payload.Description = &description
	}
	if enterprise := row[HeaderEnterprise]; enterprise != "" && enterprise != "." {
		m.Payload.EnterpriseOID = &enterprise
	}
	if trapType, err := strconv.ParseInt(row[HeaderTrapType], 10, 64); err == nil {
		m.Payload.TrapType = &trapType
	}
	if trapSubType, err := strconv.ParseInt(row[HeaderTrapSubType], 10, 64); err == nil {
		m.Payload.TrapSubType = &trapSubType
	}
	// security info is using the following format:
	// INFORM, SNMP v3, user traptest, context test
	// INFORM, SNMP v2c, community test
	secInfoRaw := row[HeaderSecurity]
	m.parseSecurityInfo(secInfoRaw)
	varRaw := row[HeaderVarBinds]
	m.parseValues(varRaw)

	return nil
}

func ParserWorker(
	i int,
	wg *sync.WaitGroup,
	parseChan <-chan []byte,
	messageChan chan<- *Message,
) {
	defer wg.Done()
	processed := metrics.ParserProcessed.With(prometheus.Labels{"worker": strconv.Itoa(i)})
	succeeded := metrics.ParserSucceeded.With(prometheus.Labels{"worker": strconv.Itoa(i)})
	dropped := metrics.ParserDropped.With(prometheus.Labels{"worker": strconv.Itoa(i)})
	for raw := range parseChan {
		processed.Inc()
		var msg Message
		if err := msg.UnmarshalText(raw); err != nil {
			log.Debug().Err(err).Str("data", string(raw)).Msg("message parsing failed")
			dropped.Inc()
		} else {
			msg.Metadata.Eta = time.Now()
			messageChan <- &msg
			succeeded.Inc()
		}
	}
}
