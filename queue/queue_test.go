package queue

import (
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

type tType struct {
	eta time.Time
	d   int
}

func (t tType) Eta() time.Time {
	return t.eta
}

func TestQueue(t *testing.T) {
	q := NewQueue[tType](
		log.Logger,
		3,
		time.Second,
		nil,
		Counter{},
	)
	defer q.Close()
	qSend := q.SendChannel()
	qRecv := q.ReceiveChannel()
	qSend <- tType{
		eta: time.Now(),
		d:   1,
	}
	val := <-qRecv
	assert.Equal(t, 1, val.d)
	assert.Equal(t, 0, q.Len())
	// simulate full queue
	qSend <- tType{
		eta: time.Now(),
		d:   1,
	}
	qSend <- tType{
		eta: time.Now().Add(time.Second),
		d:   2,
	}
	qSend <- tType{
		eta: time.Now(),
		d:   3,
	}
	qSend <- tType{
		eta: time.Now(),
		d:   4,
	}
	time.Sleep(10 * time.Millisecond)
	assert.Equal(t, 3, q.Len())
	// test priority queue
	val1 := <-qRecv
	val2 := <-qRecv
	// the first value is buffered, it's not priority queue yet
	assert.Equal(t, 1, val1.d)
	// 2 has later Eta(), that's why it has 3 first
	assert.Equal(t, 3, val2.d)
}
