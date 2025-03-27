package main

import (
	"context"
	"fmt"
	"github.com/stretchr/testify/assert"
	tc "github.com/testcontainers/testcontainers-go"
	"io"
	"os"
	"os/exec"
	"path"
	"testing"
	"time"
)

func TestFileForwarder(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	wd, err := os.Getwd()
	assert.NoError(t, err)
	tfContainer.Container.Files = []tc.ContainerFile{
		{
			HostFilePath:      path.Join(wd, "tests/forwarder_file_test.yaml"),
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

	udpPort, err := tfContainer.Resource.MappedPort(ctx, trapPort)
	if !assert.NoError(t, err) {
		return
	}
	cmdStr := defaultTestCommand(fmt.Sprintf("localhost:%d", udpPort.Int()))
	cmd := exec.Command(cmdStr[0], cmdStr[1:]...)
	err = cmd.Run()
	if !assert.NoError(t, err) {
		return
	}
	time.Sleep(time.Second)
	r, err := tfContainer.Resource.CopyFileFromContainer(
		ctx,
		"/output.log",
	)
	if !assert.NoError(t, err) {
		return
	}
	data, err := io.ReadAll(r)
	if !assert.NoError(t, err) {
		return
	}
	defaultTestAssert(t, data, 7)
	_ = r.Close()
}
