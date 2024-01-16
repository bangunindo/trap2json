package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"github.com/bangunindo/trap2json/forwarder"
	"github.com/bangunindo/trap2json/metrics"
	"github.com/bangunindo/trap2json/snmp"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

func GetSnmptrapDProcess() (*os.Process, error) {
	f, err := os.Open(snmp.PidFilePath)
	if err != nil {
		return nil, errors.Wrap(err, "failed opening pid file")
	}
	defer f.Close()
	pidRaw, err := io.ReadAll(f)
	if err != nil {
		return nil, errors.Wrap(err, "failed reading pid file")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidRaw)))
	if err != nil {
		return nil, errors.Wrap(err, "corrupted pid file")
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return nil, errors.Wrap(err, "can't find process")
	}
	return process, nil
}

func TerminateSnmptrapD() {
	logger := log.With().Str("module", "snmptrapd_monitor").Logger()
	logger.Info().Msg("terminating snmptrapd process")
	process, err := GetSnmptrapDProcess()
	if err != nil {
		logger.Warn().
			Err(err).
			Msg("failed getting snmptrapd process")
		return
	}
	err = process.Signal(syscall.SIGTERM)
	if err != nil {
		logger.Warn().
			Err(err).
			Msg("failed sending terminate signal")
		return
	}
	_, err = process.Wait()
	if err != nil {
		logger.Warn().
			Err(err).
			Msg("can't terminate process")
		return
	}
	logger.Info().Msg("snmptrapd terminated")
}

// SplitAt implements bufio.SplitFunc to split byte stream using predefined substring
func SplitAt(substring string) func(data []byte, atEOF bool) (advance int, token []byte, err error) {
	searchBytes := []byte(substring)
	searchLen := len(searchBytes)
	return func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		dataLen := len(data)
		if atEOF && dataLen == 0 {
			return 0, nil, nil
		}
		if i := bytes.Index(data, searchBytes); i >= 0 {
			return i + searchLen, data[0:i], nil
		}
		if atEOF {
			return dataLen, data, nil
		}
		return 0, nil, nil
	}
}

func Run(ctx context.Context, c config, r io.Reader, noSnmpTrapD bool) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	signal.Notify(sig, syscall.SIGTERM)

	log.Info().Msg("loading MIBs")
	if loadedModules, err := snmp.InitMIBTranslator(path.Join(defaultConfigPath, "mibs")); err != nil {
		log.Warn().Err(err).Msg("failed initiating MIB parser, some data might be unavailable")
	} else {
		log.Trace().Strs("modules", loadedModules).Msg("MIB modules loaded")
	}

	topWg := new(sync.WaitGroup)
	var promServer *http.Server
	if c.Prometheus.Enable {
		http.Handle(c.Prometheus.Path, promhttp.Handler())
		addr := fmt.Sprintf(":%d", c.Prometheus.Port)
		promServer = &http.Server{
			Addr: addr,
		}
		// start prometheus exporter
		topWg.Add(1)
		go func() {
			defer topWg.Done()
			log.Info().Msgf("starting prometheus exporter at %s", addr)
			if err := promServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatal().Err(err).Msg("prometheus exporter failed to start")
			}
		}()
		// and terminate when terminate signal received
		go func() {
			<-ctx.Done()
			_ = promServer.Shutdown(context.Background())
			log.Info().Msg("prometheus exporter exited")
		}()
	}

	go func() {
		select {
		case <-sig:
			log.Info().Msg("received termination signal")
			cancel()
		case <-ctx.Done():
		}
	}()
	if !noSnmpTrapD {
		topWg.Add(1)
		// terminate snmptrapd when we receive terminate signal
		go func() {
			defer topWg.Done()
			<-ctx.Done()
			TerminateSnmptrapD()
		}()
	}

	parseChan := make(chan []byte)
	forwarderChan := make(chan *snmp.Message)
	parseWg := new(sync.WaitGroup)
	forwarderWg := new(sync.WaitGroup)
	// spawn parser workers
	for i := 0; i < c.ParseWorkers; i++ {
		parseWg.Add(1)
		go snmp.ParserWorker(i+1, parseWg, parseChan, forwarderChan)
	}
	// spawn forwarders
	forwarderWg.Add(1)
	go forwarder.StartForwarders(forwarderWg, c.Forwarders, forwarderChan)

	bufferSize, err := c.SnmpTrapD.GetBufferSize()
	if err != nil {
		log.Warn().Err(err).Msg("failed parsing snmptrapd.buffer_size")
		bufferSize = snmp.DefaultBufferSize
	}
	buf := make([]byte, bufferSize)
	scanner := bufio.NewScanner(r)
	scanner.Split(SplitAt(c.SnmpTrapD.MagicEnd))
	scanner.Buffer(buf, bufferSize)
	magicBegin := []byte(c.SnmpTrapD.MagicBegin)
	magicBeginLen := len(magicBegin)
	log.Info().Msg("trap2json started")
	// Scan() will stop when snmptrapd is successfully terminated since it will
	// close os.Stdin stream
	for scanner.Scan() {
		metrics.SnmpTrapDProcessed.Inc()
		line := scanner.Bytes()
		metrics.SnmpTrapDProcessedBytes.Add(float64(len(line)))
		log.Trace().Bytes("data", line).Msg("received data")
		idx := bytes.LastIndex(line, magicBegin)
		if idx < 0 {
			log.Debug().Bytes("data", line).Msg("dropping data")
			metrics.SnmpTrapDDropped.Inc()
			continue
		}
		msg := make([]byte, len(line)-magicBeginLen-idx)
		copy(msg, line[idx+magicBeginLen:])
		log.Trace().Bytes("data", msg).Msg("sending data")
		parseChan <- msg
		metrics.SnmpTrapDSucceeded.Inc()
	}
	if err := scanner.Err(); err != nil {
		log.Error().Err(err).Msg("scanner error")
		// in case of scanner error, cancel should be called manually
		cancel()
	}
	// drain all channels
	close(parseChan)
	parseWg.Wait()
	close(forwarderChan)
	forwarderWg.Wait()
	cancel()
	topWg.Wait()
}
