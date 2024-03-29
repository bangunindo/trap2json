package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type Config struct {
	Enable bool
	Path   string
	Port   int
}

var (
	SnmpTrapDProcessedBytes = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "trap2json_snmptrapd_processed_bytes",
		},
	)
	SnmpTrapDProcessed = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "trap2json_snmptrapd_processed",
		},
	)
	SnmpTrapDDropped = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "trap2json_snmptrapd_dropped",
		},
	)
	SnmpTrapDSucceeded = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "trap2json_snmptrapd_succeeded",
		},
	)
	ParserProcessed = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "trap2json_parser_processed",
		},
		[]string{"worker"},
	)
	ParserDropped = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "trap2json_parser_dropped",
		},
		[]string{"worker"},
	)
	ParserSucceeded = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "trap2json_parser_succeeded",
		},
		[]string{"worker"},
	)
	CorrelateProcessed = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "trap2json_correlate_processed",
		},
	)
	CorrelateSkipped = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "trap2json_correlate_skipped",
		},
	)
	CorrelateFailed = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "trap2json_correlate_failed",
		},
	)
	CorrelateRetried = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "trap2json_correlate_retried",
		},
	)
	CorrelateSucceeded = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "trap2json_correlate_succeeded",
		},
	)
	CorrelateQueueFilled = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "trap2json_correlate_queue_filled",
		},
	)
	CorrelateQueueCapacity = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "trap2json_correlate_queue_capacity",
		},
	)
	ForwarderProcessed = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "trap2json_forwarder_processed",
		},
		[]string{"index", "type", "id"},
	)
	ForwarderDropped = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "trap2json_forwarder_dropped",
		},
		[]string{"index", "type", "id"},
	)
	ForwarderRetried = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "trap2json_forwarder_retried",
		},
		[]string{"index", "type", "id"},
	)
	ForwarderFiltered = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "trap2json_forwarder_filtered",
		},
		[]string{"index", "type", "id"},
	)
	ForwarderSucceeded = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "trap2json_forwarder_succeeded",
		},
		[]string{"index", "type", "id"},
	)
	ForwarderLookupFailed = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "trap2json_forwarder_lookup_failed",
		},
		[]string{"index", "type", "id"},
	)
	ForwarderQueueFilled = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "trap2json_forwarder_queue_filled",
		},
		[]string{"index", "type", "id"},
	)
	ForwarderQueueCapacity = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "trap2json_forwarder_queue_capacity",
		},
		[]string{"index", "type", "id"},
	)
)
