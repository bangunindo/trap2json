package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/bangunindo/trap2json/logger"
	"github.com/bangunindo/trap2json/snmp"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"io"
	"os"
	"testing"
	"time"
)

func TestRun(t *testing.T) {
	var i int
	for {
		jsonF := fmt.Sprintf("test_files/%04d.json", i)
		confF := fmt.Sprintf("test_files/%04d.yml", i)
		logF := fmt.Sprintf("test_files/%04d.log", i)

		conf, err := parseConfig(confF)
		if err != nil {
			break
		}
		logger.InitLogger(conf.Logger, os.Stderr)
		outChan := make(chan *snmp.Message, 5)
		conf.Forwarders[0].Mock.OutChannel = outChan
		conf.ParseWorkers = 1

		log, err := os.Open(logF)
		if !assert.NoError(t, err) {
			break
		}

		jsonFOpen, err := os.Open(jsonF)
		if !assert.NoError(t, err) {
			break
		}
		jsonBytes, err := io.ReadAll(jsonFOpen)
		assert.NoError(t, err)
		var jsonExpected map[string]any
		err = json.Unmarshal(jsonBytes, &jsonExpected)
		assert.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			Run(ctx, conf, log, true)
			cancel()
		}()
		cleanShutdown := false
		select {
		case <-ctx.Done():
			cleanShutdown = true
		case <-time.After(60 * time.Second):
			assert.NoError(t, errors.New("timeout"))
			cancel()
		}

		if cleanShutdown {
			msg := <-outChan
			var jsonActual map[string]any
			err = json.Unmarshal(msg.MessageJSON, &jsonActual)
			assert.NoError(t, err)
			delete(jsonExpected, "time")
			delete(jsonActual, "time")
			assert.Equal(t, jsonExpected, jsonActual)
		}
		close(outChan)

		i++
	}
}
