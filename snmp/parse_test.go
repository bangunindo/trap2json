package snmp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMessage_UnmarshalText_Issue31(t *testing.T) {
	var m Message
	err := m.UnmarshalText([]byte(`172.28.42.43|UDP: [172.17.1.65]:33332->[172.17.1.66]:10162|1763411072|4320884|Enterprise Specific|.1.3.6.1.4.1.8072.2.3.0.1|TRAP, SNMP v1, community public|6|.17|`))
	if assert.NoError(t, err) && assert.NotNil(t, m.Payload.TrapSubType) {
		assert.Equal(t, int64(17), *m.Payload.TrapSubType)
	}
}

func TestMessage_UnmarshalText(t *testing.T) {
	var m Message
	err := m.UnmarshalText([]byte(`0.0.0.0|UDP: [192.168.1.2]:8002->[192.168.1.1]:10162|1688807209|0|Cold Start|.|TRAP2, SNMP v2c, community public|0|0|.1.3.6.1.2.1.1.3.0 = Timeticks: (26402425) 3 days, 1:20:24.25	.1.3.6.1.6.3.1.1.4.1.0 = OID: .1.3.6.1.4.1.2378.1.2.1.0.1	.1.3.6.1.4.1.2378.1.2.1.1.1.1.1.203118860 = INTEGER: 203118860	.1.3.6.1.4.1.2378.1.2.1.1.1.1.2.203118860 = STRING: EMS=[NgNms/Collector=SNMP]/ManagedElement=[IP=10.1.1.1]	.1.3.6.1.4.1.2378.1.2.1.1.1.1.3.203118860 = INTEGER: physicalTerminationPoint(6)	.1.3.6.1.4.1.2378.1.2.1.1.1.1.4.203118860 = STRING: 2023-7-8,8:57:45.6,+0:0	.1.3.6.1.4.1.2378.1.2.1.1.1.1.5.203118860 = STRING: 2023-7-8,9:6:48.9,+0:0	.1.3.6.1.4.1.2378.1.2.1.1.1.1.6.203118860 = INTEGER: false(2)	.1.3.6.1.4.1.2378.1.2.1.1.1.1.7.203118860 = STRING: EQPT	.1.3.6.1.4.1.2378.1.2.1.1.1.1.8.203118860 = STRING: Radio interface is down	.1.3.6.1.4.1.2378.1.2.1.1.1.1.9.203118860 = STRING: 606:Radio interface is down:EPGP=[MC-ABC-1=1]/PTP=[port=1]	.1.3.6.1.4.1.2378.1.2.1.1.1.1.10.203118860 = INTEGER: 1	.1.3.6.1.4.1.2378.1.2.1.1.1.1.11.203118860 = STRING: N/A	.1.3.6.1.4.1.2378.1.2.1.1.1.1.12.203118860 = INTEGER: warning(5)	.1.3.6.1.4.1.2378.1.2.1.1.1.1.13.203118860 = INTEGER: equipmentAlarm(3)	.1.3.6.1.4.1.2378.1.2.1.1.1.1.14.203118860 = INTEGER: notApplicable(0)	.1.3.6.1.4.1.2378.1.2.1.1.1.1.16.203118860 = STRING: REPEATER1 to REPEATER2/Radio-1	.1.3.6.1.4.1.2378.1.2.1.1.1.1.17.203118860 = Hex-STRING: 49 50 2D 32 30 4E 	.1.3.6.1.4.1.2378.1.2.1.1.1.1.18.203118860 = Hex-STRING: 52 45 50 45 41 54 
45 52 31 	.1.3.6.1.4.1.2378.1.2.1.1.1.1.19.203118860 = ""	.1.3.6.1.4.1.2378.1.2.1.1.1.1.20.203118860 = IpAddress: 10.1.1.1	.1.3.6.1.4.1.2378.1.2.1.1.1.1.21.203118860 = ""	.1.3.6.1.4.1.2378.1.2.1.1.1.1.22.203118860 = INTEGER: 606	.1.3.6.1.4.1.2378.1.2.1.1.1.1.23.203118860 = INTEGER: 268452033	.1.3.6.1.4.1.2378.1.2.1.1.1.1.24.203118860 = INTEGER: 2	.1.3.6.1.4.1.2378.1.2.1.1.1.1.25.203118860 = Hex-STRING: 31 30 2E 31 2E 31 2E 31 `))
	assert.NoError(t, err)
	assert.Equal(t, 26, len(m.Payload.Values))
	if assert.True(t, m.Payload.UptimeSeconds != nil) {
		assert.Equal(t, 264024.25, *m.Payload.UptimeSeconds)
	}
	assert.Equal(t, "192.168.1.2", m.Payload.SrcAddress)
	assert.False(t, m.Payload.AgentAddress != nil)
	assert.Equal(t, "TRAP2", m.Payload.PDUVersion)
	assert.Equal(t, "v2c", m.Payload.SNMPVersion)
	if assert.True(t, m.Payload.Community != nil) {
		assert.Equal(t, "public", *m.Payload.Community)
	}
	if assert.True(t, m.Payload.EnterpriseOID != nil) {
		assert.Equal(t, ".1.3.6.1.4.1.2378.1.2.1.0.1", *m.Payload.EnterpriseOID)
	}
	assert.False(t, m.Payload.EnterpriseMIBName != nil)
	assert.False(t, m.Payload.User != nil)
	assert.False(t, m.Payload.Context != nil)
	if assert.True(t, m.Payload.Description != nil) {
		assert.Equal(t, "Cold Start", *m.Payload.Description)
	}
	if assert.True(t, m.Payload.TrapType != nil) {
		assert.Equal(t, int64(0), *m.Payload.TrapType)
	}
	if assert.True(t, m.Payload.TrapSubType != nil) {
		assert.Equal(t, int64(0), *m.Payload.TrapSubType)
	}
	assert.Equal(t, "73h20m24.25s", m.Payload.Values[0].Value)
	assert.Equal(t, 264024.25, m.Payload.Values[0].ValueDetail.Raw)
	assert.False(t, m.Payload.Values[1].Value.(string) != "")
	assert.Equal(t, ".1.3.6.1.4.1.2378.1.2.1.0.1", m.Payload.Values[1].ValueDetail.Raw)
	assert.Equal(t, 203118860, m.Payload.Values[2].Value)
	assert.Equal(t, "EMS=[NgNms/Collector=SNMP]/ManagedElement=[IP=10.1.1.1]", m.Payload.Values[3].Value)
	assert.Equal(t, "physicalTerminationPoint", m.Payload.Values[4].Value)
	assert.Equal(t, 6, m.Payload.Values[4].ValueDetail.Raw)
	assert.Equal(t, "2023-7-8,8:57:45.6,+0:0", m.Payload.Values[5].Value)
	assert.Equal(t, "2023-7-8,9:6:48.9,+0:0", m.Payload.Values[6].Value)
	assert.Equal(t, "false", m.Payload.Values[7].Value)
	assert.Equal(t, 2, m.Payload.Values[7].ValueDetail.Raw)
	assert.Equal(t, "EQPT", m.Payload.Values[8].Value)
	assert.Equal(t, "Radio interface is down", m.Payload.Values[9].Value)
	assert.Equal(t, "606:Radio interface is down:EPGP=[MC-ABC-1=1]/PTP=[port=1]", m.Payload.Values[10].Value)
	assert.Equal(t, 1, m.Payload.Values[11].Value)
	assert.Equal(t, "N/A", m.Payload.Values[12].Value)
	assert.Equal(t, "warning", m.Payload.Values[13].Value)
	assert.Equal(t, 5, m.Payload.Values[13].ValueDetail.Raw)
	assert.Equal(t, "equipmentAlarm", m.Payload.Values[14].Value)
	assert.Equal(t, 3, m.Payload.Values[14].ValueDetail.Raw)
	assert.Equal(t, "notApplicable", m.Payload.Values[15].Value)
	assert.Equal(t, 0, m.Payload.Values[15].ValueDetail.Raw)
	assert.Equal(t, "REPEATER1 to REPEATER2/Radio-1", m.Payload.Values[16].Value)
	assert.Equal(t, "IP-20N", m.Payload.Values[17].Value)
	assert.Equal(t, "49502D32304E", m.Payload.Values[17].ValueDetail.Hex)
	assert.Equal(t, "REPEATER1", m.Payload.Values[18].Value)
	assert.Equal(t, "524550454154455231", m.Payload.Values[18].ValueDetail.Hex)
	assert.Nil(t, m.Payload.Values[19].Value)
	assert.Equal(t, "10.1.1.1", m.Payload.Values[20].Value)
	assert.Nil(t, m.Payload.Values[21].Value)
	assert.Equal(t, 606, m.Payload.Values[22].Value)
	assert.Equal(t, 268452033, m.Payload.Values[23].Value)
	assert.Equal(t, 2, m.Payload.Values[24].Value)
	assert.Equal(t, "10.1.1.1", m.Payload.Values[25].Value)
	assert.Equal(t, "31302E312E312E31", m.Payload.Values[25].ValueDetail.Hex)
}
