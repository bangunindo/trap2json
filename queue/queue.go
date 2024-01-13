package queue

import (
	"context"
	qq "github.com/Workiva/go-datastructures/queue"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"time"
)

type Item interface {
	Eta() time.Time
}

type item struct {
	i Item
}

func (m *item) Compare(other qq.Item) int {
	otherM := other.(*item)
	if otherM.i.Eta().Equal(m.i.Eta()) {
		return 0
	} else if otherM.i.Eta().After(m.i.Eta()) {
		return -1
	} else {
		return 1
	}
}

type Counter struct {
	Processed   prometheus.Counter
	Drop        prometheus.Counter
	Passthrough prometheus.Counter
	QueueCap    prometheus.Gauge
	QueueLen    prometheus.Gauge
}

type Queue[T Item] struct {
	ctx             context.Context
	cancel          context.CancelFunc
	q               *qq.PriorityQueue
	logger          zerolog.Logger
	size            int
	sendChan        chan T
	passthroughChan chan T
	recvChan        chan T
	minDelay        time.Duration
	maxDelay        time.Duration
	flushTimeout    time.Duration
	counter         Counter
}

func (q *Queue[T]) SendChannel() chan<- T {
	return q.sendChan
}

func (q *Queue[T]) sendWorker() {
	for m := range q.sendChan {
		if q.counter.Processed != nil {
			q.counter.Processed.Inc()
		}
		if q.size == 0 || q.q.Len() < q.size {
			err := q.q.Put(&item{m})
			if err != nil {
				if q.passthroughChan == nil {
					q.logger.Error().Msg("unexpected error, queue is closed")
					if q.counter.Drop != nil {
						q.counter.Drop.Inc()
					}
				} else {
					q.logger.Warn().Msg("unexpected error, queue is closed")
					if q.counter.Passthrough != nil {
						q.counter.Passthrough.Inc()
					}
					q.passthroughChan <- m
				}
			}
		} else {
			q.logger.Warn().Msg("queue is full, consider increasing queue_size")
			if q.passthroughChan == nil {
				if q.counter.Drop != nil {
					q.counter.Drop.Inc()
				}
			} else {
				if q.counter.Passthrough != nil {
					q.counter.Passthrough.Inc()
				}
				q.passthroughChan <- m
			}
		}
	}
	timeout := time.After(q.flushTimeout)
outer:
	for {
		select {
		case <-timeout:
			break outer
		default:
			if q.q.Empty() {
				break outer
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	q.q.Dispose()
}

func (q *Queue[T]) ReceiveChannel() <-chan T {
	return q.recvChan
}

func (q *Queue[T]) receiveWorker() {
	var msg *item
	for {
		if q.q.Disposed() {
			break
		}
		for {
			m := q.q.Peek()
			if m == nil {
				time.Sleep(10 * time.Millisecond)
				continue
			} else {
				msg = m.(*item)
				if msg.i.Eta().Before(time.Now()) {
					break
				} else {
					time.Sleep(10 * time.Millisecond)
					continue
				}
			}
		}
		if m, err := q.q.Get(1); err == nil {
			msg = m[0].(*item)
			q.recvChan <- msg.i.(T)
		} else {
			break
		}
	}
	close(q.recvChan)
	q.cancel()
}

func (q *Queue[T]) monitorWorker() {
	if q.counter.QueueCap != nil && q.counter.QueueLen != nil {
		q.counter.QueueCap.Set(float64(q.size))
	outer:
		for {
			select {
			case <-q.ctx.Done():
				break outer
			case <-time.After(time.Second):
				q.counter.QueueLen.Set(float64(q.q.Len()))
			}
		}
	}
}

func (q *Queue[T]) Len() int {
	return q.q.Len()
}

func (q *Queue[T]) Close() {
	close(q.sendChan)
}

func (q *Queue[T]) Done() <-chan struct{} {
	return q.ctx.Done()
}

func NewQueue[T Item](
	logger zerolog.Logger,
	size int,
	flushTimeout time.Duration,
	passthroughChan chan T,
	counter Counter,
) *Queue[T] {
	q := &Queue[T]{
		q:               qq.NewPriorityQueue(size, true),
		logger:          logger,
		size:            size,
		sendChan:        make(chan T, 10),
		recvChan:        make(chan T),
		passthroughChan: passthroughChan,
		flushTimeout:    flushTimeout,
		counter:         counter,
	}
	q.ctx, q.cancel = context.WithCancel(context.Background())
	go q.sendWorker()
	go q.receiveWorker()
	go q.monitorWorker()
	return q
}
