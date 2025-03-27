package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/stretchr/testify/assert"
	tc "github.com/testcontainers/testcontainers-go"
	"io"
	"net/http"
	"os/exec"
	"path"
	"testing"
	"time"
)

func TestHTTPForwarder(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	confPath := "tests/forwarder_http_test.yaml"
	if localOS[operatingSystem] {
		confPath = "tests/forwarder_http_local_test.yaml"
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
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		defer cancelMsg()
		data, err := io.ReadAll(r.Body)
		if !assert.NoError(t, err) {
			return
		}
		defaultTestAssert(t, data, 7)
	})
	srv := &http.Server{
		Addr: ":9789",
	}
	go func() {
		err := srv.ListenAndServe()
		if !errors.Is(err, http.ErrServerClosed) {
			panic(err)
		}
	}()
	// wait for http server to start
	time.Sleep(10 * time.Millisecond)

	udpPort, err := tfContainer.Resource.MappedPort(ctx, trapPort)
	assert.NoError(t, err)
	cmdStr := defaultTestCommand(fmt.Sprintf("localhost:%d", udpPort.Int()))
	cmd := exec.Command(cmdStr[0], cmdStr[1:]...)
	err = cmd.Run()
	if !assert.NoError(t, err) {
		return
	}
	<-ctxMsg.Done()
	srv.Shutdown(ctx)
}
