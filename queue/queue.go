package queue

import (
	qq "github.com/Workiva/go-datastructures/queue"
	"time"
)

type Item interface {
	Eta() time.Time
	Retries() int
}

type Queue[T Item] struct {
	q       *qq.PriorityQueue
	size    int
	inChan  <-chan T
	outChan chan<- T
}

func (q *Queue) Close() {
	max()
}

func NewQueue(size int) *Queue {

}
