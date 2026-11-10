package certauth

import (
	"github.com/alastria/isbe-onboarding/tsaservice"
	"github.com/ansrivas/fiberprometheus/v2"
	"github.com/gofiber/fiber/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// newMetricsRegistry returns the registry served at /metrics. It holds the Go
// runtime and process collectors and the TSA metrics; fiberprometheus adds the
// HTTP metrics to it. A fresh registry per server avoids duplicate-registration
// panics when several servers are created in one process (tests).
func newMetricsRegistry() (*prometheus.Registry, error) {
	reg := prometheus.NewRegistry()
	if err := reg.Register(collectors.NewGoCollector()); err != nil {
		return nil, err
	}
	if err := reg.Register(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{})); err != nil {
		return nil, err
	}
	if err := tsaservice.RegisterMetrics(reg); err != nil {
		return nil, err
	}
	return reg, nil
}

// setupMetrics serves /metrics on app and installs the HTTP metrics middleware.
func setupMetrics(app *fiber.App) error {
	reg, err := newMetricsRegistry()
	if err != nil {
		return err
	}
	p := fiberprometheus.NewWithRegistry(reg, "certauth", "http", "", nil)
	p.RegisterAt(app, "/metrics")
	app.Use(p.Middleware)
	return nil
}
