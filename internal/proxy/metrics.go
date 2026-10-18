package proxy

import (
	"github.com/curtisnewbie/miso/miso"
	"github.com/prometheus/client_golang/prometheus"
)

// Operator-facing metrics are package-level and registered exactly once, so any
// number of Proxy values (and any test) share the same series instead of
// re-registering them.
var (
	requestsTotal     = miso.NewPromCounter("homeproxy_requests_total")
	authFailuresTotal = miso.NewPromCounter("homeproxy_auth_failures_total")
	bytesUpTotal      = miso.NewPromCounter("homeproxy_bytes_up_total")
	bytesDownTotal    = miso.NewPromCounter("homeproxy_bytes_down_total")
	dialFailuresTotal = miso.NewPromCounter("homeproxy_dial_failures_total")
	dialDuration      = miso.NewPromHisto("homeproxy_dial_duration")

	// miso has no gauge factory, so the gauge is hand-registered on the default
	// registerer like the other metrics.
	tunnelsActive = prometheus.NewGauge(prometheus.GaugeOpts{Name: "homeproxy_tunnels_active"})
)

func init() {
	prometheus.MustRegister(tunnelsActive)
}
