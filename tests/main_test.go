package main

import (
	"context"
	"log"
	"os"
	"path"
	"testing"

	"github.com/go-json-experiment/json"
	"github.com/stretchr/testify/assert"
	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const networkName = "t2j-testing"
const trapPort = "10162/udp"

var operatingSystem = ""
var localOS = map[string]bool{
	"OrbStack": true,
}

var wd, _ = os.Getwd()

type ValueDetail struct {
	Raw any     `json:"raw,omitempty" mapstructure:"raw"`
	Hex *string `json:"hex,omitempty" mapstructure:"hex"`
}
type Value struct {
	OID         string      `json:"oid" mapstructure:"oid"`
	MIBName     string      `json:"mib_name" mapstructure:"mib_name"`
	Type        string      `json:"type" mapstructure:"type"`
	NativeType  string      `json:"native_type" mapstructure:"native_type"`
	Value       any         `json:"value" mapstructure:"value"`
	ValueDetail ValueDetail `json:"value_detail" mapstructure:"value_detail"`
}
type Message struct {
	LocalTime         *string  `json:"time" mapstructure:"time"`
	UptimeSeconds     *float64 `json:"uptime_seconds" mapstructure:"uptime_seconds"`
	SourceAddress     *string  `json:"source_address" mapstructure:"source_address"`
	AgentAddress      *string  `json:"agent_address" mapstructure:"agent_address"`
	PDUVersion        *string  `json:"pdu_version" mapstructure:"pdu_version"`
	SNMPVersion       *string  `json:"snmp_version" mapstructure:"snmp_version"`
	Community         *string  `json:"community" mapstructure:"community"`
	EnterpriseOID     *string  `json:"enterprise_oid" mapstructure:"enterprise_oid"`
	EnterpriseMIBName *string  `json:"enterprise_mib_name" mapstructure:"enterprise_mib_name"`
	User              *string  `json:"user" mapstructure:"user"`
	Context           *string  `json:"context" mapstructure:"context"`
	Description       *string  `json:"description" mapstructure:"description"`
	TrapType          *int     `json:"trap_type" mapstructure:"trap_type"`
	TrapSubType       *int     `json:"trap_sub_type" mapstructure:"trap_sub_type"`
	Values            []Value  `json:"values" mapstructure:"values"`
}

var tfContainer = &ContainerInfo{
	Container: tc.ContainerRequest{
		FromDockerfile: tc.FromDockerfile{
			Context:    ".",
			Dockerfile: "Dockerfile",
		},
		Name:         "t2j-trap2json",
		Networks:     []string{networkName},
		ExposedPorts: []string{trapPort},
		WaitingFor:   wait.ForLog("trap2json started"),
	},
}
var containers = []*ContainerInfo{
	{
		Container: tc.ContainerRequest{
			Image:        "bitnami/kafka:3.5.0",
			Name:         "t2j-kafka",
			ExposedPorts: []string{"9094:9094/tcp"},
			Networks:     []string{networkName},
			Env: map[string]string{
				"ALLOW_PLAINTEXT_LISTENER":                 "yes",
				"KAFKA_CFG_AUTO_CREATE_TOPICS_ENABLE":      "true",
				"KAFKA_CFG_LISTENERS":                      "PLAINTEXT://:9092,CONTROLLER://:9093,EXTERNAL://:9094",
				"KAFKA_CFG_ADVERTISED_LISTENERS":           "PLAINTEXT://t2j-kafka:9092,EXTERNAL://localhost:9094",
				"KAFKA_CFG_LISTENER_SECURITY_PROTOCOL_MAP": "CONTROLLER:PLAINTEXT,EXTERNAL:PLAINTEXT,PLAINTEXT:PLAINTEXT",
			},
			WaitingFor: wait.ForLog("Kafka Server started"),
		},
	},
	{
		Container: tc.ContainerRequest{
			Image:        "eclipse-mosquitto:2.0.15",
			Name:         "t2j-mqtt",
			Networks:     []string{networkName},
			ExposedPorts: []string{"1883/tcp"},
			WaitingFor:   wait.ForLog("mosquitto version 2.0.15 running"),
			Mounts: tc.ContainerMounts{
				tc.ContainerMount{
					Source: tc.GenericBindMountSource{
						HostPath: path.Join(wd, "/tests/forwarder_mqtt_test.conf"),
					},
					Target: "/mosquitto/config/mosquitto.conf",
				},
			},
		},
	},
	{
		Container: tc.ContainerRequest{
			Image:        "postgres:15",
			Name:         "t2j-postgres",
			Networks:     []string{networkName},
			ExposedPorts: []string{"5432/tcp"},
			Env: map[string]string{
				"POSTGRES_PASSWORD": "test",
				"POSTGRES_USER":     "test",
				"POSTGRES_DB":       "zabbix",
			},
			WaitingFor: wait.ForLog("database system is ready to accept connections"),
		},
	},
	{
		Container: tc.ContainerRequest{
			Image:        "zabbix/zabbix-server-pgsql:ubuntu-7.2.2",
			Name:         "t2j-zabbix-server",
			Networks:     []string{networkName},
			ExposedPorts: []string{"10051/tcp"},
			Env: map[string]string{
				"DB_SERVER_HOST":    "t2j-postgres",
				"POSTGRES_USER":     "test",
				"POSTGRES_PASSWORD": "test",
				"POSTGRES_DB":       "zabbix",
			},
			WaitingFor: wait.ForLog("thread started"),
		},
	},
	{
		Container: tc.ContainerRequest{
			Image:        "zabbix/zabbix-web-nginx-pgsql:ubuntu-7.2.2",
			Name:         "t2j-zabbix-web",
			Networks:     []string{networkName},
			ExposedPorts: []string{"8080/tcp"},
			Env: map[string]string{
				"ZBX_SERVER_HOST":   "t2j-zabbix-server",
				"DB_SERVER_HOST":    "t2j-postgres",
				"POSTGRES_USER":     "test",
				"POSTGRES_PASSWORD": "test",
				"POSTGRES_DB":       "zabbix",
			},
			WaitingFor: wait.ForLog("ready to handle connections"),
		},
	},
	{
		Container: tc.ContainerRequest{
			Image:        "zabbix/zabbix-proxy-sqlite3:ubuntu-6.4.4",
			Name:         "t2j-zabbix-proxy-01",
			Networks:     []string{networkName},
			ExposedPorts: []string{"10051/tcp"},
			Env: map[string]string{
				"ZBX_SERVER_HOST": "t2j-zabbix-server",
				"ZBX_HOSTNAME":    "zabbix-proxy-01",
			},
			WaitingFor: wait.ForLog("thread started"),
		},
	},
	{
		Container: tc.ContainerRequest{
			Image:        "zabbix/zabbix-proxy-sqlite3:ubuntu-6.4.4",
			Name:         "t2j-zabbix-proxy-02",
			Networks:     []string{networkName},
			ExposedPorts: []string{"10051/tcp"},
			Env: map[string]string{
				"ZBX_SERVER_HOST": "t2j-zabbix-server",
				"ZBX_HOSTNAME":    "zabbix-proxy-02",
			},
			WaitingFor: wait.ForLog("thread started"),
		},
	},
}
var defaultTestCommand = func(host string) []string {
	return []string{
		"snmptrap",
		"-v2c",
		"-c", "public",
		host,
		"3000",
		"SNMPv2-MIB::snmpTrap",
		"IF-MIB::ifHighSpeed.1", "u", "1000",
		"IF-MIB::ifName.1", "s", "eth0",
		"IF-MIB::ifAdminStatus", "i", "2",
		"IP-MIB::ipAdEntAddr", "a", "127.0.0.1",
		"HOST-RESOURCES-MIB::hrSystemDate", "s", "2023-6-7,1:0:0.0,+7:0",
	}
}

func defaultTestAssert(t *testing.T, data []byte, expectedLen int) Message {
	m := Message{}
	err := json.Unmarshal(data, &m)
	assert.NoError(t, err)
	if assert.NotNil(t, m.Community) {
		assert.Equal(t, "public", *m.Community)
	}
	if assert.Equal(t, expectedLen, len(m.Values)) {
		assert.Equal(t, "30s", m.Values[0].Value)
		assert.Equal(t, "SNMPv2-MIB::snmpTrap", m.Values[1].Value)
		assert.Equal(t, 1000.0, m.Values[2].Value)
		assert.Equal(t, "eth0", m.Values[3].Value)
		assert.Equal(t, "down", m.Values[4].Value)
		assert.Equal(t, "127.0.0.1", m.Values[5].Value)
		assert.Equal(t, "2023-06-07T01:00:00+07:00", m.Values[6].Value)
	}
	return m
}

func GetContainerByName(name string) *ContainerInfo {
	for _, c := range containers {
		if c.Container.Name == name {
			return c
		}
	}
	return nil
}

func TestMain(m *testing.M) {
	ctx := context.Background()
	network, err := tc.GenericNetwork(
		ctx,
		tc.GenericNetworkRequest{
			NetworkRequest: tc.NetworkRequest{
				Name: networkName,
			},
		},
	)
	if err != nil {
		log.Fatalf("failed creating network %s", err)
	}
	dc, err := tc.NewDockerClient()
	if err != nil {
		log.Fatalf("failed connecting docker %s", err)
	}
	inf, err := dc.Info(ctx)
	if err != nil {
		log.Fatalf("failed getting docker info %s", err)
	}
	operatingSystem = inf.OperatingSystem

	for _, c := range containers {
		ctr, err := tc.GenericContainer(
			ctx,
			tc.GenericContainerRequest{
				ContainerRequest: c.Container,
				Started:          true,
			},
		)
		if err != nil {
			log.Fatalf("failed creating container %s", err)
		}
		c.Resource = ctr
		if c.Container.Name == "t2j-kafka" {
			_, _, err = c.Resource.Exec(ctx, []string{
				"kafka-topics.sh",
				"--bootstrap-server",
				"localhost:9092",
				"--topic",
				"t2jtest",
				"--create",
				"--partitions",
				"1",
				"--replication-factor",
				"1",
			})
			if err != nil {
				log.Fatalf("failed creating kafka topic %s", err)
			}
		}
	}

	code := m.Run()

	for _, c := range containers {
		if err := c.Resource.Terminate(ctx); err != nil {
			log.Printf("failed terminating container %s\n", c.Container.Name)
		}
	}
	_ = network.Remove(ctx)

	os.Exit(code)
}
