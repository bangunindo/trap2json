package main

import (
	"context"
	"fmt"
	"github.com/bangunindo/trap2json/logger"
	"github.com/bangunindo/trap2json/snmp"
	"github.com/go-json-experiment/json"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRun(t *testing.T) {
	var i int
	for {
		jsonFGlob := fmt.Sprintf("test_files/%04d_*.json", i)
		confFGlob := fmt.Sprintf("test_files/%04d_*.yml", i)
		logFGlob := fmt.Sprintf("test_files/%04d_*.log", i)

		jsonFList, err := filepath.Glob(jsonFGlob)
		assert.NoError(t, err)
		if len(jsonFList) == 0 {
			break
		}
		assert.Equal(t, 1, len(jsonFList))
		jsonF := jsonFList[0]
		confFList, err := filepath.Glob(confFGlob)
		assert.NoError(t, err)
		if len(confFList) == 0 {
			break
		}
		assert.Equal(t, 1, len(confFList))
		confF := confFList[0]
		logFList, err := filepath.Glob(logFGlob)
		assert.NoError(t, err)
		if len(logFList) == 0 {
			break
		}
		assert.Equal(t, 1, len(logFList))
		logF := logFList[0]

		conf, err := parseConfig(confF)
		if !assert.NoError(t, err) {
			i++
			continue
		}
		logger.InitLogger(conf.Logger, os.Stderr)
		outChan := make(chan *snmp.Message, 5)
		conf.Forwarders[0].Mock.OutChannel = outChan
		conf.ParseWorkers = 1

		log, err := os.Open(logF)
		if !assert.NoError(t, err) {
			i++
			continue
		}

		jsonFOpen, err := os.Open(jsonF)
		if !assert.NoError(t, err) {
			i++
			continue
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
			err = json.Unmarshal(msg.Metadata.MessageJSON, &jsonActual)
			assert.NoError(t, err)
			timeActual, ok := jsonActual["time"]
			assert.True(t, ok)
			if assert.IsType(t, "", timeActual) {
				_, err = time.Parse(time.RFC3339, timeActual.(string))
				assert.NoError(t, err)
			}
			delete(jsonExpected, "time")
			delete(jsonActual, "time")
			assert.Equal(t, jsonExpected, jsonActual)
		}
		close(outChan)

		i++
	}
}
