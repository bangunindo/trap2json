package correlate

import (
	"github.com/bangunindo/trap2json/correlate/backend"
	"github.com/bangunindo/trap2json/helper"
	"github.com/bangunindo/trap2json/metrics"
	"github.com/bangunindo/trap2json/queue"
	"github.com/bangunindo/trap2json/snmp"
	"github.com/expr-lang/expr"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"sync"
)

type counter struct {
	succeeded prometheus.Counter
	skipped   prometheus.Counter
	failed    prometheus.Counter
	retried   prometheus.Counter
}

type Correlate struct {
	backend backend.Backend
	wg      *sync.WaitGroup
	queue   *queue.Queue[*snmp.Message]
	out     chan<- *snmp.Message
	conds   []*Condition
	retry   helper.AutoRetry
	logger  zerolog.Logger
	ctr     counter
}

func (c *Correlate) Retry(m *snmp.Message, err error) {
	if c.retry.Enable && m.Metadata.Retries < c.retry.MaxRetries {
		eta := m.ComputeEta(
			c.retry.MinDelay.Duration,
			c.retry.MaxDelay.Duration,
		)
		m.Metadata.Retries++
		m.Metadata.Eta = eta
		c.ctr.retried.Inc()
		c.logger.Debug().Err(err).Msg("retrying to correlate message")
		c.queue.SendChannel() <- m
	} else {
		c.failed(m, err)
	}
}

func (c *Correlate) failed(m *snmp.Message, err error) {
	c.logger.Warn().Err(err).Msg("failed correlating message")
	c.ctr.failed.Inc()
	c.out <- m
}

func (c *Correlate) Close() {
	if c == nil {
		return
	}
	c.queue.Close()
}

func (c *Correlate) SendChannel() chan<- *snmp.Message {
	return c.queue.SendChannel()
}

func (c *Correlate) CorrelateWorker() {
	defer c.wg.Done()
outer:
	for m := range c.queue.ReceiveChannel() {
	inner:
		for _, cond := range c.conds {
			matchRaw, err := expr.Run(cond.Match, m.Payload)
			if err != nil {
				c.failed(m, errors.Wrap(err, "failed evaluating match"))
				continue outer
			}
			match, ok := matchRaw.(bool)
			if !ok {
				c.failed(m, errors.New("failed casting match result"))
				continue outer
			}
			if !match {
				continue inner
			}
			keyRaw, err := expr.Run(cond.Identifier, m.Payload)
			if err != nil {
				c.failed(m, errors.Wrap(err, "failed evaluating identifier"))
				continue outer
			}
			key, ok := keyRaw.(string)
			if !ok {
				c.failed(m, errors.New("failed casting key result"))
				continue outer
			}
			isClearRaw, err := expr.Run(cond.Clear, m.Payload)
			if err != nil {
				c.failed(m, errors.Wrap(err, "failed evaluating clear"))
				continue outer
			}
			isClear, ok := isClearRaw.(bool)
			if !ok {
				c.failed(m, errors.New("failed casting clear result"))
				continue outer
			}
			if isClear {
				payload, exists, err := c.backend.Pop(key)
				if err != nil {
					c.Retry(m, err)
					continue outer
				}
				if !exists {
					c.failed(m, errors.New("raise event doesn't exists"))
					continue outer
				} else {
					c.ctr.succeeded.Inc()
					t := payload.Time()
					d := m.Payload.Time.Sub(t)
					m.Payload.Correlate = &snmp.Correlate{
						ID:              payload.ID,
						RaisedTime:      t,
						Duration:        helper.Duration{Duration: d},
						DurationSeconds: d.Seconds(),
					}
				}
			} else {
				id := uuid.NewString()
				err = c.backend.Set(
					key,
					backend.Data{
						RaisedTimeSeconds: m.Payload.Time.Unix(),
						RaisedTimeNanos:   int64(m.Payload.Time.Nanosecond()),
						ID:                id,
					},
				)
				if err != nil {
					c.Retry(m, err)
					continue outer
				} else {
					c.ctr.succeeded.Inc()
				}
			}
			c.out <- m
			continue outer
		}
		c.ctr.skipped.Inc()
	}
}

func NewCorrelate(c Config, wg *sync.WaitGroup, fwdChan chan<- *snmp.Message) (*Correlate, error) {
	be, err := backend.NewBackend(
		c.BackendURL,
		c.TTL.Duration,
		c.Timeout.Duration,
	)
	if err != nil {
		return nil, err
	}
	var conds []*Condition
	for i, condConf := range c.Conditions {
		cond, err := parseCondition(condConf)
		if err != nil {
			return nil, errors.Wrapf(err, "condition index %d", i)
		}
		conds = append(conds, cond)
	}
	logger := log.
		With().
		Str("module", "correlate").
		Logger()
	q := queue.NewQueue(
		logger,
		c.QueueSize,
		c.ShutdownWaitTime.Duration,
		fwdChan,
		queue.Counter{
			Processed:   metrics.CorrelateProcessed,
			Drop:        metrics.CorrelateFailed,
			Passthrough: metrics.CorrelateSkipped,
			QueueCap:    metrics.CorrelateQueueCapacity,
			QueueLen:    metrics.CorrelateQueueFilled,
		},
	)
	cor := &Correlate{
		backend: be,
		wg:      wg,
		queue:   q,
		out:     fwdChan,
		conds:   conds,
		retry:   c.AutoRetry,
		logger:  logger,
		ctr: counter{
			succeeded: metrics.CorrelateSucceeded,
			skipped:   metrics.CorrelateSkipped,
			failed:    metrics.CorrelateFailed,
			retried:   metrics.CorrelateRetried,
		},
	}
	return cor, nil
}
