package main

import (
	"context"
	"fmt"
	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/stretchr/testify/assert"
	tc "github.com/testcontainers/testcontainers-go"
	"io"
	"os/exec"
	"path"
	"testing"
	"time"
)

func TestMqttForwarder(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	tfContainer.Container.Mounts = tc.ContainerMounts{
		tc.ContainerMount{
			Source: tc.GenericBindMountSource{
				HostPath: path.Join(wd, "tests/forwarder_mqtt_test.yaml"),
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

	mqttContainer := GetContainerByName("t2j-mqtt")
	if !assert.NotNil(t, mqttContainer) {
		return
	}
	mqttPort, err := mqttContainer.Resource.MappedPort(ctx, "1883/tcp")
	assert.NoError(t, err)
	ctxMsg, cancelMsg := context.WithCancel(ctx)
	subsFn := func(client mqtt.Client, msg mqtt.Message) {
		defaultTestAssert(t, msg.Payload(), 7)
		cancelMsg()
	}
	opts := mqtt.NewClientOptions()
	opts.AddBroker(fmt.Sprintf("tcp://localhost:%d", mqttPort.Int()))
	opts.SetClientID("testing")
	opts.SetKeepAlive(2 * time.Second)
	opts.SetDefaultPublishHandler(subsFn)
	opts.SetPingTimeout(1 * time.Second)
	c := mqtt.NewClient(opts)
	token := c.Connect()
	token.Wait()
	if !assert.NoError(t, token.Error()) {
		return
	}
	defer c.Disconnect(1000)
	token = c.Subscribe("t2jtest", 0, nil)
	token.Wait()
	if !assert.NoError(t, token.Error()) {
		return
	}

	udpPort, err := tfContainer.Resource.MappedPort(ctx, trapPort)
	assert.NoError(t, err)
	cmdStr := defaultTestCommand(fmt.Sprintf("localhost:%d", udpPort.Int()))
	cmd := exec.Command(cmdStr[0], cmdStr[1:]...)
	err = cmd.Run()
	if !assert.NoError(t, err) {
		return
	}
	<-ctxMsg.Done()
}
