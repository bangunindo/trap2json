package queue

import (
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

type tType int

func (t tType) Eta() time.Time {
	return time.Now()
}

func TestQueue(t *testing.T) {
	q := NewQueue[tType](
		log.Logger,
		1,
		time.Second, time.Second, time.Second,
		nil,
		Counter{},
	)
	defer q.Close()
	qSend := q.SendChannel()
	qRecv := q.ReceiveChannel()
	qSend <- 1
	val := <-qRecv
	assert.Equal(t, 1, int(val))
	assert.Equal(t, 0, q.Len())
	// simulate full queue
	qSend <- 1
	qSend <- 1
	time.Sleep(10 * time.Millisecond)
	assert.Equal(t, 1, q.Len())
}
