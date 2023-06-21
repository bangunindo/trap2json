package main

import (
	"context"
	"fmt"
	"github.com/segmentio/kafka-go"
	"github.com/stretchr/testify/assert"
	tc "github.com/testcontainers/testcontainers-go"
	"io"
	"os"
	"os/exec"
	"path"
	"testing"
	"time"
)

func TestKafkaForwarder(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	wd, err := os.Getwd()
	assert.NoError(t, err)
	tfContainer.Container.Mounts = tc.ContainerMounts{
		tc.ContainerMount{
			Source: tc.GenericBindMountSource{
				HostPath: path.Join(wd, "tests/forwarder_kafka_test.yaml"),
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
	kafkaContainer := GetContainerByName("t2j-kafka")
	if !assert.NotNil(t, kafkaContainer) {
		return
	}
	cmdStr := defaultTestCommand(fmt.Sprintf("localhost:%d", udpPort.Int()))
	cmd := exec.Command(cmdStr[0], cmdStr[1:]...)
	err = cmd.Run()
	if !assert.NoError(t, err) {
		return
	}
	r := kafka.NewReader(kafka.ReaderConfig{
		Brokers:   []string{fmt.Sprintf("localhost:9094")},
		Topic:     "t2jtest",
		Partition: 0,
	})
	defer r.Close()
	err = r.SetOffset(0)
	assert.NoError(t, err)
	ctxMsg, cancelMsg := context.WithTimeout(ctx, 2*time.Second)
	defer cancelMsg()
	mK, err := r.ReadMessage(ctxMsg)
	assert.NoError(t, err)
	defaultTestAssert(t, mK.Value, 7)
}
