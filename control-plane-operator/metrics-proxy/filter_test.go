package metricsproxy

import (
	"bytes"
	"math"
	"strings"
	"sync"
	"testing"

	"github.com/openshift/hypershift/support/metrics"

	corev1 "k8s.io/api/core/v1"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"google.golang.org/protobuf/proto"
)

func TestFilter_Apply(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		metricsSet    metrics.MetricsSet
		componentName string
		families      map[string]*dto.MetricFamily
		wantNames     []string
	}{
		{
			name:          "all metrics set passes all families through",
			metricsSet:    metrics.MetricsSetAll,
			componentName: "kube-apiserver",
			families: map[string]*dto.MetricFamily{
				"apiserver_request_total": createMetricFamily("apiserver_request_total"),
				"unrelated_metric":        createMetricFamily("unrelated_metric"),
			},
			wantNames: []string{"apiserver_request_total", "unrelated_metric"},
		},
		{
			name:          "telemetry keeps configured kube-apiserver families",
			metricsSet:    metrics.MetricsSetTelemetry,
			componentName: "kube-apiserver",
			families: map[string]*dto.MetricFamily{
				"apiserver_storage_objects":           createMetricFamily("apiserver_storage_objects"),
				"apiserver_request_total":             createMetricFamily("apiserver_request_total"),
				"some_unrelated_metric":               createMetricFamily("some_unrelated_metric"),
				"apiserver_current_inflight_requests": createMetricFamily("apiserver_current_inflight_requests"),
			},
			wantNames: []string{
				"apiserver_storage_objects",
				"apiserver_request_total",
				"apiserver_current_inflight_requests",
			},
		},
		{
			name:          "unknown component passes through",
			metricsSet:    metrics.MetricsSetTelemetry,
			componentName: "unknown-component",
			families: map[string]*dto.MetricFamily{
				"metric_one": createMetricFamily("metric_one"),
				"metric_two": createMetricFamily("metric_two"),
			},
			wantNames: []string{"metric_one", "metric_two"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := NewFilter(tt.metricsSet).Apply(tt.componentName, tt.families)
			if len(got) != len(tt.wantNames) {
				t.Fatalf("Apply() returned %d families, want %d", len(got), len(tt.wantNames))
			}
			for _, name := range tt.wantNames {
				if _, ok := got[name]; !ok {
					t.Errorf("Apply() missing expected family %q", name)
				}
			}
		})
	}
}

func TestFilter_SREKnownWithoutRulesFailsClosedAndUnknownPassesThrough(t *testing.T) {
	loadSREFilterConfig(t, "{}")
	filter := NewFilter(metrics.MetricsSetSRE)

	knownFamily := createMetricFamily("etcd_server_leader_changes_seen_total")
	if got := filter.Apply("etcd", map[string]*dto.MetricFamily{knownFamily.GetName(): knownFamily}); len(got) != 0 {
		t.Fatalf("known component with omitted SRE rules returned %d families, want none", len(got))
	}
	if got, err := filter.ApplyExposition("etcd", knownFamily, []byte("etcd_server_leader_changes_seen_total 1\n")); err == nil || len(got) != 0 {
		t.Fatalf("known component with omitted SRE rules returned %q, error %v; want fail closed", got, err)
	}

	unknownFamily := createMetricFamily("custom_metric")
	families := map[string]*dto.MetricFamily{unknownFamily.GetName(): unknownFamily}
	if got := filter.Apply("custom-component", families); got[unknownFamily.GetName()] != unknownFamily {
		t.Fatal("unknown component did not pass its family through")
	}
	input := []byte("custom_metric 42\n")
	got, err := filter.ApplyExposition("custom-component", unknownFamily, input)
	if err != nil || !bytes.Equal(got, input) {
		t.Fatalf("unknown component ApplyExposition() = %q, %v; want unchanged exposition", got, err)
	}
}

func TestFilter_SREOrderedKeepDropUsesSourceLabelsAndSeparators(t *testing.T) {
	loadSREFilterConfig(t, `kubeAPIServer:
- action: keep
  regex: 'api;west'
  sourceLabels: [app, region]
- action: drop
  regex: 'api\|west\|private'
  separator: '|'
  sourceLabels: [app, region, visibility]
`)

	family := &dto.MetricFamily{
		Name: proto.String("request_count"),
		Type: dto.MetricType_GAUGE.Enum(),
		Metric: []*dto.Metric{
			gaugeMetric(1, "app", "api", "region", "west", "visibility", "public"),
			gaugeMetric(2, "app", "api", "region", "west", "visibility", "private"),
			gaugeMetric(3, "app", "api", "region", "east", "visibility", "public"),
		},
	}

	filtered, err := NewFilter(metrics.MetricsSetSRE).ApplyExposition("kube-apiserver", family, encodeMetricFamily(t, family))
	if err != nil {
		t.Fatalf("ApplyExposition() error: %v", err)
	}
	parsed := parseMetricFamilies(t, filtered)
	got := parsed["request_count"]
	if got == nil || len(got.Metric) != 1 {
		t.Fatalf("parsed filtered family = %#v, want exactly one sample; exposition:\n%s", got, filtered)
	}
	labels := metricLabels(got.Metric[0])
	if labels["region"] != "west" || labels["visibility"] != "public" || got.Metric[0].GetGauge().GetValue() != 1 {
		t.Errorf("kept sample = labels %v, value %v; want west/public, 1", labels, got.Metric[0].GetGauge().GetValue())
	}
}

func TestFilter_SREExplicitEmptySeparator(t *testing.T) {
	loadSREFilterConfig(t, `kubeAPIServer:
- action: keep
  regex: apiwest
  sourceLabels: [app, region]
  separator: ''
`)
	family := &dto.MetricFamily{
		Name:   proto.String("request_count"),
		Type:   dto.MetricType_GAUGE.Enum(),
		Metric: []*dto.Metric{gaugeMetric(1, "app", "api", "region", "west")},
	}
	filtered, err := NewFilter(metrics.MetricsSetSRE).ApplyExposition("kube-apiserver", family, encodeMetricFamily(t, family))
	if err != nil || len(filtered) == 0 {
		t.Fatalf("empty separator rule dropped matching sample: %q, %v", filtered, err)
	}
}

func TestFilter_ApplyExpositionHistogramBucketsAndSuffixSamples(t *testing.T) {
	loadSREFilterConfig(t, `kubeAPIServer:
- action: keep
  regex: 'request_duration_seconds_(bucket|sum|count)'
  sourceLabels: [__name__]
- action: drop
  regex: '0.5'
  sourceLabels: [le]
`)
	family := &dto.MetricFamily{
		Name: proto.String("request_duration_seconds"),
		Type: dto.MetricType_HISTOGRAM.Enum(),
		Metric: []*dto.Metric{{
			Label: []*dto.LabelPair{{Name: proto.String("method"), Value: proto.String("GET")}},
			Histogram: &dto.Histogram{
				SampleCount: proto.Uint64(4),
				SampleSum:   proto.Float64(1.5),
				Bucket: []*dto.Bucket{{
					CumulativeCount: proto.Uint64(2),
					UpperBound:      proto.Float64(0.5),
				}},
			},
		}},
	}

	filtered, err := NewFilter(metrics.MetricsSetSRE).ApplyExposition("kube-apiserver", family, encodeMetricFamily(t, family))
	if err != nil {
		t.Fatalf("ApplyExposition() error: %v", err)
	}
	parsed := parseMetricFamilies(t, filtered)
	got := parsed["request_duration_seconds"]
	if got == nil || len(got.Metric) != 1 || got.Metric[0].Histogram == nil {
		t.Fatalf("parsed filtered histogram = %#v, want one histogram", got)
	}
	histogram := got.Metric[0].Histogram
	if len(histogram.Bucket) != 1 || histogram.Bucket[0].GetUpperBound() != float64PositiveInfinity() {
		t.Errorf("filtered histogram buckets = %#v, want only implicit +Inf bucket", histogram.Bucket)
	}
	if histogram.GetSampleCount() != 4 || histogram.GetSampleSum() != 1.5 {
		t.Errorf("filtered histogram count/sum = %d/%v, want 4/1.5", histogram.GetSampleCount(), histogram.GetSampleSum())
	}
}

func TestFilter_ApplyExpositionSummaryQuantile(t *testing.T) {
	loadSREFilterConfig(t, `kubeAPIServer:
- action: keep
  regex: '0.9'
  sourceLabels: [quantile]
`)
	family := &dto.MetricFamily{
		Name: proto.String("request_duration_seconds"),
		Type: dto.MetricType_SUMMARY.Enum(),
		Metric: []*dto.Metric{{
			Summary: &dto.Summary{
				SampleCount: proto.Uint64(5),
				SampleSum:   proto.Float64(2.5),
				Quantile: []*dto.Quantile{
					{Quantile: proto.Float64(0.5), Value: proto.Float64(0.4)},
					{Quantile: proto.Float64(0.9), Value: proto.Float64(0.8)},
				},
			},
		}},
	}

	filtered, err := NewFilter(metrics.MetricsSetSRE).ApplyExposition("kube-apiserver", family, encodeMetricFamily(t, family))
	if err != nil {
		t.Fatalf("ApplyExposition() error: %v", err)
	}
	parsed := parseMetricFamilies(t, filtered)
	got := parsed["request_duration_seconds"]
	if got == nil || len(got.Metric) != 1 || got.Metric[0].Summary == nil {
		t.Fatalf("parsed filtered summary = %#v, want one summary", got)
	}
	quantiles := got.Metric[0].Summary.Quantile
	if len(quantiles) != 1 || quantiles[0].GetQuantile() != 0.9 || quantiles[0].GetValue() != 0.8 {
		t.Errorf("filtered summary quantiles = %#v, want only quantile 0.9 with value 0.8", quantiles)
	}
}

func TestFilter_Apply_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	filter := NewFilter(metrics.MetricsSetTelemetry)
	families := map[string]*dto.MetricFamily{
		"apiserver_storage_objects": createMetricFamily("apiserver_storage_objects"),
		"apiserver_request_total":   createMetricFamily("apiserver_request_total"),
	}
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				_ = filter.Apply("kube-apiserver", families)
			}
		}()
	}
	wg.Wait()
}

func loadSREFilterConfig(t *testing.T, config string) {
	t.Helper()
	cm := &corev1.ConfigMap{Data: map[string]string{metrics.SREConfigurationConfigMapKey: config}}
	if err := metrics.LoadSREMetricsSetConfigurationFromConfigMap(cm); err != nil {
		t.Fatalf("load SRE metrics config: %v", err)
	}
	t.Cleanup(func() {
		if err := metrics.LoadSREMetricsSetConfigurationFromConfigMap(&corev1.ConfigMap{Data: map[string]string{metrics.SREConfigurationConfigMapKey: "{}"}}); err != nil {
			t.Errorf("reset SRE metrics config: %v", err)
		}
	})
}

func encodeMetricFamily(t *testing.T, family *dto.MetricFamily) []byte {
	t.Helper()
	var output bytes.Buffer
	if err := expfmt.NewEncoder(&output, expfmt.NewFormat(expfmt.TypeTextPlain)).Encode(family); err != nil {
		t.Fatalf("encode metric family: %v", err)
	}
	return output.Bytes()
}

func parseMetricFamilies(t *testing.T, exposition []byte) map[string]*dto.MetricFamily {
	t.Helper()
	parser := expfmt.NewTextParser(model.LegacyValidation)
	families, err := parser.TextToMetricFamilies(strings.NewReader(string(exposition)))
	if err != nil {
		t.Fatalf("parse exposition: %v\n%s", err, exposition)
	}
	return families
}

func gaugeMetric(value float64, labels ...string) *dto.Metric {
	metric := &dto.Metric{Gauge: &dto.Gauge{Value: proto.Float64(value)}}
	for i := 0; i < len(labels); i += 2 {
		metric.Label = append(metric.Label, &dto.LabelPair{Name: proto.String(labels[i]), Value: proto.String(labels[i+1])})
	}
	return metric
}

func metricLabels(metric *dto.Metric) map[string]string {
	labels := make(map[string]string, len(metric.Label))
	for _, label := range metric.Label {
		labels[label.GetName()] = label.GetValue()
	}
	return labels
}

func float64PositiveInfinity() float64 {
	return math.Inf(1)
}

func createMetricFamily(name string) *dto.MetricFamily {
	metricType := dto.MetricType_GAUGE
	return &dto.MetricFamily{Name: &name, Type: &metricType}
}
