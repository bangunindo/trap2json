package correlate

import (
	"github.com/bangunindo/trap2json/correlate/backend"
	"github.com/bangunindo/trap2json/metrics"
	"github.com/bangunindo/trap2json/snmp"
	"github.com/prometheus/client_golang/prometheus"
	"strconv"
	"sync"
)

type Correlate struct {
}

func CorrelateWorker(
	i int,
	wg *sync.WaitGroup,
	backend backend.Backend,
	messageIn <-chan snmp.Message,
	messageOut chan<- snmp.Message,
) {
	defer wg.Done()
	processed := metrics.CorrelateProcessed.With(prometheus.Labels{"worker": strconv.Itoa(i)})
	succeeded := metrics.CorrelateSucceeded.With(prometheus.Labels{"worker": strconv.Itoa(i)})
	skipped := metrics.CorrelateSkipped.With(prometheus.Labels{"worker": strconv.Itoa(i)})
	failed := metrics.CorrelateFailed.With(prometheus.Labels{"worker": strconv.Itoa(i)})
}
