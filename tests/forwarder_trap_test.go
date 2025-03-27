package main

import (
	"context"
	"fmt"
	g "github.com/gosnmp/gosnmp"
	"github.com/stretchr/testify/assert"
	tc "github.com/testcontainers/testcontainers-go"
	"io"
	"net"
	"os/exec"
	"path"
	"testing"
	"time"
)

func TestTrapForwarder(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	confPath := "tests/forwarder_trap_test.yaml"
	if localOS[operatingSystem] {
		confPath = "tests/forwarder_trap_local_test.yaml"
	}
	tfContainer.Container.Files = []tc.ContainerFile{
		{
			HostFilePath:      path.Join(wd, confPath),
			ContainerFilePath: "/etc/trap2json/config.yml",
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

	ctxMsg, cancelMsg := context.WithCancel(ctx)
	trapHandler := func(s *g.SnmpPacket, u *net.UDPAddr) {
		if assert.Equal(t, 7, len(s.Variables)) {
			assert.Equal(t, 3000, int(s.Variables[0].Value.(uint32)))
			assert.Equal(t, ".1.3.6.1.6.3.1.1.4", s.Variables[1].Value)
			assert.Equal(t, 1000, int(s.Variables[2].Value.(uint)))
			assert.Equal(t, "eth0", string(s.Variables[3].Value.([]byte)))
			assert.Equal(t, 2, s.Variables[4].Value)
			assert.Equal(t, "127.0.0.1", s.Variables[5].Value)
			assert.Equal(t, "2023-6-7,1:0:0.0,+7:0", string(s.Variables[6].Value.([]byte)))
		}
		cancelMsg()
	}
	tl := g.NewTrapListener()
	tl.OnNewTrap = trapHandler
	tl.Params = g.Default
	listenAddr := "0.0.0.0:10150"
	go func() {
		err := tl.Listen(listenAddr)
		assert.NoError(t, err)
	}()
	<-tl.Listening()

	udpPort, err := tfContainer.Resource.MappedPort(ctx, trapPort)
	assert.NoError(t, err)
	cmdStr := defaultTestCommand(fmt.Sprintf("localhost:%d", udpPort.Int()))
	cmd := exec.Command(cmdStr[0], cmdStr[1:]...)
	err = cmd.Run()
	if !assert.NoError(t, err) {
		return
	}
	<-ctxMsg.Done()
	tl.Close()
}
