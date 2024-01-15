package correlate

import (
	"github.com/bangunindo/trap2json/correlate/backend"
	"github.com/bangunindo/trap2json/metrics"
	"github.com/bangunindo/trap2json/queue"
	"github.com/bangunindo/trap2json/snmp"
	"github.com/prometheus/client_golang/prometheus"
	"strconv"
	"sync"
)

type Correlate struct {
	backend backend.Backend
	wg      *sync.WaitGroup
	queue   queue.Queue[*snmp.Message]
}

func (c *Correlate) CorrelateWorker(
	i int,
) {
	defer c.wg.Done()
	_ = metrics.CorrelateProcessed.With(prometheus.Labels{"worker": strconv.Itoa(i)})
	_ = metrics.CorrelateSucceeded.With(prometheus.Labels{"worker": strconv.Itoa(i)})
	_ = metrics.CorrelateSkipped.With(prometheus.Labels{"worker": strconv.Itoa(i)})
	_ = metrics.CorrelateFailed.With(prometheus.Labels{"worker": strconv.Itoa(i)})
}
