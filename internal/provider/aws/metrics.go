package aws

import (
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/sdk/metric"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

// NewMeterProvider creates a new OpenTelemetry MeterProvider with Prometheus exporter
// and registers it with the global metrics registry.
func NewMeterProvider() (*metric.MeterProvider, error) {
	metricExporter, err := prometheus.New(
		prometheus.WithRegisterer(metrics.Registry),
		prometheus.WithNamespace("aws"),
	)
	if err != nil {
		return nil, err
	}

	meterProvider := metric.NewMeterProvider(
		metric.WithReader(metricExporter),
	)
	return meterProvider, nil
}
