package main

import (
	"context"
	"fmt"
	"github.com/cavaliercoder/go-zabbix"
	"github.com/stretchr/testify/assert"
	tc "github.com/testcontainers/testcontainers-go"
	"io"
	"os/exec"
	"path"
	"strings"
	"testing"
	"time"
)

func getZabbixSession(t *testing.T, ctx context.Context) *zabbix.Session {
	zabbixWeb := GetContainerByName("t2j-zabbix-web")
	if !assert.NotNil(t, zabbixWeb) {
		return nil
	}
	zabbixPort, err := zabbixWeb.Resource.MappedPort(ctx, "8080/tcp")
	if !assert.NoError(t, err) {
		return nil
	}
	session := &zabbix.Session{
		URL: fmt.Sprintf("http://localhost:%d/api_jsonrpc.php", zabbixPort.Int()),
	}
	_, err = session.GetVersion()
	assert.NoError(t, err)
	params := map[string]string{
		"username": "Admin",
		"password": "zabbix",
	}
	resp, err := session.Do(zabbix.NewRequest("user.login", params))
	if assert.NoError(t, err) {
		err = resp.Bind(&session.Token)
		assert.NoError(t, err)
	}
	return session
}

func zabbixSetup(t *testing.T, session *zabbix.Session) (hostIds [][2]string) {
	respTemplate := make(map[string][]string)
	// create template
	resp, err := session.Do(zabbix.NewRequest(
		"template.create",
		map[string]any{
			"host": "Zabbix trapper template",
			"groups": map[string]any{
				"groupid": 1,
			},
		},
	))
	assert.NoError(t, err)
	err = resp.Bind(&respTemplate)
	assert.NoError(t, err)
	templateId := respTemplate["templateids"][0]
	// create zabbix trapper item
	_, err = session.Do(zabbix.NewRequest(
		"item.create",
		map[string]any{
			"name":   "SNMP Trap",
			"key_":   "snmptrap.json",
			"hostid": templateId,
			// zabbix trapper type
			"type": 2,
			// text item type
			"value_type": 4,
		},
	))
	assert.NoError(t, err)
	// create 4 hosts
	// each is for zabbix server, zabbix proxy 1, zabbix proxy 2, and default host
	hostResp := make(map[string][]string)
	resp, err = session.Do(zabbix.NewRequest(
		"host.create",
		map[string]any{
			"host": "test-host",
			"templates": []map[string]any{
				{
					"templateid": templateId,
				},
			},
			"groups": []map[string]any{
				{
					"groupid": "4",
				},
			},
			"interfaces": []map[string]any{
				{
					"type":  2,
					"main":  1,
					"useip": 1,
					"ip":    "10.0.0.0",
					"dns":   "",
					"port":  "161",
					"details": map[string]any{
						"version":   2,
						"community": "public",
					},
				},
			},
		},
	))
	assert.NoError(t, err)
	err = resp.Bind(&hostResp)
	assert.NoError(t, err)
	hostIds = append(hostIds, [2]string{hostResp["hostids"][0], "10.0.0.0"})
	resp, err = session.Do(zabbix.NewRequest(
		"host.create",
		map[string]any{
			"host": "test-host-server",
			"templates": []map[string]any{
				{
					"templateid": templateId,
				},
			},
			"groups": []map[string]any{
				{
					"groupid": "4",
				},
			},
			"interfaces": []map[string]any{
				{
					"type":  2,
					"main":  1,
					"useip": 1,
					"ip":    "10.0.0.1",
					"dns":   "",
					"port":  "161",
					"details": map[string]any{
						"version":   2,
						"community": "public",
					},
				},
			},
		},
	))
	assert.NoError(t, err)
	err = resp.Bind(&hostResp)
	assert.NoError(t, err)
	hostIds = append(hostIds, [2]string{hostResp["hostids"][0], "10.0.0.1"})
	resp, err = session.Do(zabbix.NewRequest(
		"host.create",
		map[string]any{
			"host": "test-host-proxy-01",
			"templates": []map[string]any{
				{
					"templateid": templateId,
				},
			},
			"groups": []map[string]any{
				{
					"groupid": "4",
				},
			},
			"interfaces": []map[string]any{
				{
					"type":  2,
					"main":  1,
					"useip": 1,
					"ip":    "10.0.0.2",
					"dns":   "",
					"port":  "161",
					"details": map[string]any{
						"version":   2,
						"community": "public",
					},
				},
			},
		},
	))
	assert.NoError(t, err)
	err = resp.Bind(&hostResp)
	assert.NoError(t, err)
	hostIds = append(hostIds, [2]string{hostResp["hostids"][0], "10.0.0.2"})
	hostProxy1 := hostResp["hostids"][0]
	resp, err = session.Do(zabbix.NewRequest(
		"host.create",
		map[string]any{
			"host": "test-host-proxy-02",
			"templates": []map[string]any{
				{
					"templateid": templateId,
				},
			},
			"groups": []map[string]any{
				{
					"groupid": "4",
				},
			},
			"interfaces": []map[string]any{
				{
					"type":  2,
					"main":  1,
					"useip": 1,
					"ip":    "10.0.0.3",
					"dns":   "",
					"port":  "161",
					"details": map[string]any{
						"version":   2,
						"community": "public",
					},
				},
			},
		},
	))
	assert.NoError(t, err)
	err = resp.Bind(&hostResp)
	assert.NoError(t, err)
	hostIds = append(hostIds, [2]string{hostResp["hostids"][0], "10.0.0.3"})
	hostProxy2 := hostResp["hostids"][0]
	// create proxies
	_, err = session.Do(zabbix.NewRequest(
		"proxy.create",
		map[string]any{
			"host":   "zabbix-proxy-01",
			"status": 5,
			"hosts": []map[string]any{
				{
					"hostid": hostProxy1,
				},
			},
		},
	))
	assert.NoError(t, err)
	_, err = session.Do(zabbix.NewRequest(
		"proxy.create",
		map[string]any{
			"host":   "zabbix-proxy-02",
			"status": 5,
			"hosts": []map[string]any{
				{
					"hostid": hostProxy2,
				},
			},
		},
	))
	assert.NoError(t, err)
	return hostIds
}

func proxyReload(t *testing.T, ctx context.Context) {
	proxy01 := GetContainerByName("t2j-zabbix-proxy-01")
	if !assert.NotNil(t, proxy01) {
		return
	}
	proxy02 := GetContainerByName("t2j-zabbix-proxy-02")
	if !assert.NotNil(t, proxy02) {
		return
	}
	for _, c := range []*ContainerInfo{proxy01, proxy02} {
		for {
			_, _, err := c.Resource.Exec(ctx, []string{
				"zabbix_proxy",
				"-R",
				"config_cache_reload",
			})
			if !assert.NoError(t, err) {
				break
			}
			r, err := c.Resource.Logs(ctx)
			if !assert.NoError(t, err) {
				break
			}
			b, err := io.ReadAll(r)
			if !assert.NoError(t, err) {
				break
			}
			if strings.Count(string(b), "received configuration data from server") > 0 {
				break
			}
			time.Sleep(time.Second)
		}
	}
}

func zabbixAssert(t *testing.T, session *zabbix.Session, hostid [2]string) {
	resp, err := session.Do(zabbix.NewRequest(
		"history.get",
		map[string]any{
			"history": 4,
			"hostids": hostid[0],
			"output":  "extend",
			"limit":   "1",
		},
	))
	if !assert.NoError(t, err) {
		return
	}
	var historyResp []map[string]string
	err = resp.Bind(&historyResp)
	if !assert.NoError(t, err) {
		return
	}
	if assert.Equal(t, 1, len(historyResp)) {
		m := defaultTestAssert(t, []byte(historyResp[0]["value"]), 8)
		v, ok := m.Values[len(m.Values)-1].Value.(string)
		assert.True(t, ok)
		assert.Equal(t, hostid[1], v)
	}
}

func TestZabbixTrapForwarder(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	session := getZabbixSession(t, ctx)
	if !assert.NotNil(t, session) {
		return
	}
	hostIds := zabbixSetup(t, session)
	if t.Failed() {
		return
	}
	proxyReload(t, ctx)
	if t.Failed() {
		return
	}

	tfContainer.Container.Mounts = tc.ContainerMounts{
		tc.ContainerMount{
			Source: tc.GenericBindMountSource{
				HostPath: path.Join(wd, "tests/forwarder_zabbix_trap_test.yaml"),
			},
			Target:   "/etc/trap2json/config.yml",
			ReadOnly: true,
		},
	}
	setup(ctx, tfContainer)
	defer teardown(ctx, tfContainer)
	defer func() {
		if t.Failed() {
			if r, err := tfContainer.Resource.Logs(ctx); err == nil {
				if logs, err := io.ReadAll(r); err == nil {
					fmt.Println(string(logs))
				}
			}
		}
	}()

	udpPort, err := tfContainer.Resource.MappedPort(ctx, trapPort)
	assert.NoError(t, err)
	cmdStr := defaultTestCommand(fmt.Sprintf("localhost:%d", udpPort.Int()))
	for _, ipAddr := range []string{"10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		cmdNew := append(cmdStr, "SNMP-COMMUNITY-MIB::snmpTrapAddress.0", "a", ipAddr)
		cmd := exec.Command(cmdNew[0], cmdNew[1:]...)
		err = cmd.Run()
		assert.NoError(t, err)
	}
	time.Sleep(5 * time.Second)
	for _, hostId := range hostIds {
		zabbixAssert(t, session, hostId)
	}
}
