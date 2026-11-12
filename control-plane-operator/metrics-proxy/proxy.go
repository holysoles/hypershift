package metricsproxy

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-logr/logr"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"google.golang.org/protobuf/proto"
)

type ProxyHandler struct {
	log               logr.Logger
	componentProvider ComponentProvider
	targetDiscoverer  TargetDiscoverer
	scraper           *Scraper
	filter            *Filter
	labeler           *Labeler
}

func NewProxyHandler(log logr.Logger, componentProvider ComponentProvider, targetDiscoverer TargetDiscoverer, scraper *Scraper, filter *Filter, labeler *Labeler) *ProxyHandler {
	return &ProxyHandler{
		log:               log,
		componentProvider: componentProvider,
		targetDiscoverer:  targetDiscoverer,
		scraper:           scraper,
		filter:            filter,
		labeler:           labeler,
	}
}

func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Extract component name from path: /metrics/<component-name>
	path := strings.TrimPrefix(r.URL.Path, "/metrics/")
	path = strings.TrimSuffix(path, "/")
	if path == "" || strings.Contains(path, "/") {
		http.Error(w, "invalid path: expected /metrics/<component-name>", http.StatusBadRequest)
		return
	}
	componentName := path

	// Look up the component configuration.
	componentConfig, ok := h.componentProvider.GetComponent(componentName)
	if !ok {
		http.Error(w, fmt.Sprintf("unknown component: %s", componentName), http.StatusNotFound)
		return
	}

	// Authentication is enforced by the requireClientCert middleware which
	// verifies a client certificate was presented and validated against the
	// cluster-signer-ca CA bundle (via VerifyClientCertIfGiven at the TLS layer).

	// Discover pods
	targets, err := h.targetDiscoverer.Discover(ctx, componentConfig.Selector, componentConfig.MetricsPort)
	if err != nil {
		h.log.Error(err, "discovery error", "component", componentName)
		http.Error(w, "failed to discover targets", http.StatusInternalServerError)
		return
	}

	if len(targets) == 0 {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		return
	}

	// Scrape all targets
	results := h.scraper.ScrapeAll(ctx, targets, componentConfig.MetricsPath, componentConfig.MetricsScheme, componentConfig.TLSServerName, componentConfig.TLSConfig)

	// Merge, filter, and label results
	format := expfmt.NewFormat(expfmt.TypeTextPlain)
	var buf bytes.Buffer

	successes := 0
	var failedTargets []ScrapeTarget
	for i, result := range results {
		if result.Err != nil {
			h.log.Error(result.Err, "scrape error", "target", targets[i].PodName)
			failedTargets = append(failedTargets, targets[i])
			continue
		}
		successes++

		for _, sourceFamily := range result.Families {
			if sourceFamily == nil {
				continue
			}

			// Label injection mutates DTOs, so encode a copy rather than changing
			// the scraper's family data.
			family := proto.Clone(sourceFamily).(*dto.MetricFamily)
			h.labeler.Inject(map[string]*dto.MetricFamily{family.GetName(): family}, targets[i], componentName, componentConfig)

			var familyBuffer bytes.Buffer
			encoder := expfmt.NewEncoder(&familyBuffer, format)
			if err := encoder.Encode(family); err != nil {
				h.log.Error(err, "encode error")
				continue
			}
			filtered, err := h.filter.ApplyExposition(componentName, sourceFamily, familyBuffer.Bytes())
			if err != nil {
				h.log.Error(err, "metrics filtering failed", "component", componentName, "metric", sourceFamily.GetName())
				continue
			}
			_, _ = buf.Write(filtered)
		}
	}

	// Emit synthetic scrape error counter for failed targets.
	if len(failedTargets) > 0 {
		errorFamily := buildScrapeErrorMetric(componentName, failedTargets)
		var errorBuffer bytes.Buffer
		encoder := expfmt.NewEncoder(&errorBuffer, format)
		if err := encoder.Encode(errorFamily); err != nil {
			h.log.Error(err, "encode error for scrape error metric")
		} else {
			_, _ = buf.Write(errorBuffer.Bytes())
		}
	}

	if successes == 0 {
		http.Error(w, "all scrape targets failed", http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", string(format))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}

// buildScrapeErrorMetric creates a synthetic metrics_aggregator_pod_scrape_errors_total
// counter metric family with one metric per failed scrape target.
func buildScrapeErrorMetric(componentName string, failedTargets []ScrapeTarget) *dto.MetricFamily {
	name := "metrics_aggregator_pod_scrape_errors_total"
	help := "Total number of pod scrape errors per component and pod."
	metricType := dto.MetricType_COUNTER

	metrics := make([]*dto.Metric, 0, len(failedTargets))
	for _, t := range failedTargets {
		compLabel := "component"
		podLabel := "pod"
		compValue := componentName
		podValue := t.PodName
		counterValue := float64(1)

		metrics = append(metrics, &dto.Metric{
			Label: []*dto.LabelPair{
				{Name: &compLabel, Value: &compValue},
				{Name: &podLabel, Value: &podValue},
			},
			Counter: &dto.Counter{Value: &counterValue},
		})
	}

	return &dto.MetricFamily{
		Name:   &name,
		Help:   &help,
		Type:   &metricType,
		Metric: metrics,
	}
}
