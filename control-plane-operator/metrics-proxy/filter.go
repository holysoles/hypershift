package metricsproxy

import (
	"bytes"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/openshift/hypershift/support/metrics"

	prometheusoperatorv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	dto "github.com/prometheus/client_model/go"
	"google.golang.org/protobuf/proto"
)

type Filter struct {
	metricsSet metrics.MetricsSet

	mu         sync.RWMutex
	rulesCache map[string]compiledRelabelFilter
}

type compiledRelabelFilter struct {
	passThrough bool
	rules       []compiledRelabelRule
	err         error
}

type compiledRelabelRule struct {
	action       string
	sourceLabels []string
	separator    string
	regex        *regexp.Regexp
}

type emittedSample struct {
	metricName string
	metric     *dto.Metric
	extraLabel string
	extraValue string
}

func NewFilter(metricsSet metrics.MetricsSet) *Filter {
	return &Filter{
		metricsSet: metricsSet,
		rulesCache: make(map[string]compiledRelabelFilter),
	}
}

// Apply filters DTO families without mutating the source families. Since a DTO
// cannot represent a partially filtered histogram or summary, it retains a
// metric only when all of that metric's emitted samples pass. The proxy uses
// ApplyExposition to filter those child samples individually.
func (f *Filter) Apply(componentName string, families map[string]*dto.MetricFamily) map[string]*dto.MetricFamily {
	compiled := f.getCompiledRules(componentName)
	if compiled.passThrough {
		return families
	}
	if compiled.err != nil {
		return map[string]*dto.MetricFamily{}
	}

	filtered := make(map[string]*dto.MetricFamily)
	for name, family := range families {
		if family == nil {
			continue
		}
		if len(family.Metric) == 0 {
			if relabelSampleMatches(compiled.rules, emittedSample{metricName: family.GetName()}) {
				filtered[name] = family
			}
			continue
		}

		copy := proto.Clone(family).(*dto.MetricFamily)
		copy.Metric = nil
		for _, metric := range family.Metric {
			samples := emittedSamplesForMetric(family, metric)
			if len(samples) == 0 {
				continue
			}
			allMatch := true
			for _, sample := range samples {
				if !relabelSampleMatches(compiled.rules, sample) {
					allMatch = false
					break
				}
			}
			if allMatch {
				copy.Metric = append(copy.Metric, proto.Clone(metric).(*dto.Metric))
			}
		}
		if len(copy.Metric) > 0 {
			filtered[name] = copy
		}
	}
	return filtered
}

// ApplyExposition filters each sample line after expfmt has expanded histogram
// and summary DTOs into their Prometheus text representation.
func (f *Filter) ApplyExposition(componentName string, family *dto.MetricFamily, exposition []byte) ([]byte, error) {
	compiled := f.getCompiledRules(componentName)
	if compiled.passThrough {
		return exposition, nil
	}
	if compiled.err != nil {
		return nil, compiled.err
	}

	samples := emittedSamples(family)
	if len(samples) == 0 {
		return nil, nil
	}
	keep := make([]bool, len(samples))
	keepCount := 0
	for i, sample := range samples {
		keep[i] = relabelSampleMatches(compiled.rules, sample)
		if keep[i] {
			keepCount++
		}
	}
	if keepCount == 0 {
		return nil, nil
	}

	var headers, sampleLines [][]byte
	for _, line := range bytes.SplitAfter(exposition, []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		if line[0] == '#' {
			headers = append(headers, line)
		} else {
			sampleLines = append(sampleLines, line)
		}
	}
	if len(sampleLines) != len(samples) {
		return nil, fmt.Errorf("cannot filter %q exposition: expfmt emitted %d sample lines for %d DTO samples", family.GetName(), len(sampleLines), len(samples))
	}

	var filtered bytes.Buffer
	for _, header := range headers {
		filtered.Write(header)
	}
	for i, line := range sampleLines {
		if keep[i] {
			filtered.Write(line)
		}
	}
	return filtered.Bytes(), nil
}

func (f *Filter) getCompiledRules(componentName string) compiledRelabelFilter {
	f.mu.RLock()
	compiled, ok := f.rulesCache[componentName]
	f.mu.RUnlock()
	if ok {
		return compiled
	}

	compiled = f.compileRules(componentName)
	f.mu.Lock()
	if cached, ok := f.rulesCache[componentName]; ok {
		compiled = cached
	} else {
		f.rulesCache[componentName] = compiled
	}
	f.mu.Unlock()
	return compiled
}

func (f *Filter) compileRules(componentName string) compiledRelabelFilter {
	if f.metricsSet == metrics.MetricsSetAll {
		return compiledRelabelFilter{passThrough: true}
	}
	if f.metricsSet != metrics.MetricsSetTelemetry && f.metricsSet != metrics.MetricsSetSRE {
		return compiledRelabelFilter{err: fmt.Errorf("unsupported metrics set %q", f.metricsSet)}
	}

	configs := getRelabelConfigsForComponent(componentName, f.metricsSet)
	if !isKnownServiceMonitor(componentName) {
		return compiledRelabelFilter{passThrough: true}
	}
	if len(configs) == 0 {
		return compiledRelabelFilter{err: fmt.Errorf("no relabel rules configured for known ServiceMonitor %q in metrics set %q", componentName, f.metricsSet)}
	}

	compiled := compiledRelabelFilter{rules: make([]compiledRelabelRule, 0, len(configs))}
	for i, config := range configs {
		if config.Action != "keep" && config.Action != "drop" {
			return compiledRelabelFilter{err: fmt.Errorf("unsupported relabel action %q in rule %d for %q", config.Action, i, componentName)}
		}
		regex := config.Regex
		if regex == "" {
			regex = "(.*)"
		}
		matcher, err := regexp.Compile("^(?s:" + regex + ")$")
		if err != nil {
			return compiledRelabelFilter{err: fmt.Errorf("invalid relabel regex in rule %d for %q: %w", i, componentName, err)}
		}
		separator := ";"
		if config.Separator != nil {
			separator = *config.Separator
		}
		sourceLabels := make([]string, len(config.SourceLabels))
		for i, label := range config.SourceLabels {
			sourceLabels[i] = string(label)
		}
		compiled.rules = append(compiled.rules, compiledRelabelRule{
			action:       config.Action,
			sourceLabels: sourceLabels,
			separator:    separator,
			regex:        matcher,
		})
	}
	return compiled
}

func relabelSampleMatches(rules []compiledRelabelRule, sample emittedSample) bool {
	for _, rule := range rules {
		values := make([]string, len(rule.sourceLabels))
		for i, label := range rule.sourceLabels {
			values[i] = sample.labelValue(label)
		}
		matched := rule.regex.MatchString(strings.Join(values, rule.separator))
		if rule.action == "keep" && !matched || rule.action == "drop" && matched {
			return false
		}
	}
	return true
}

func (sample emittedSample) labelValue(label string) string {
	if label == "__name__" {
		return sample.metricName
	}
	if label == sample.extraLabel && sample.extraLabel != "" {
		return sample.extraValue
	}
	if sample.metric != nil {
		for _, pair := range sample.metric.Label {
			if pair.GetName() == label {
				return pair.GetValue()
			}
		}
	}
	return ""
}

func emittedSamples(family *dto.MetricFamily) []emittedSample {
	if family == nil {
		return nil
	}
	var samples []emittedSample
	for _, metric := range family.Metric {
		samples = append(samples, emittedSamplesForMetric(family, metric)...)
	}
	return samples
}

func emittedSamplesForMetric(family *dto.MetricFamily, metric *dto.Metric) []emittedSample {
	if family == nil || metric == nil {
		return nil
	}
	name := family.GetName()
	one := func(metricName, label, value string) emittedSample {
		return emittedSample{metricName: metricName, metric: metric, extraLabel: label, extraValue: value}
	}
	switch family.GetType() {
	case dto.MetricType_COUNTER, dto.MetricType_GAUGE, dto.MetricType_UNTYPED:
		return []emittedSample{one(name, "", "")}
	case dto.MetricType_SUMMARY:
		if metric.Summary == nil {
			return nil
		}
		samples := make([]emittedSample, 0, len(metric.Summary.Quantile)+2)
		for _, quantile := range metric.Summary.Quantile {
			samples = append(samples, one(name, "quantile", formatRelabelFloat(quantile.GetQuantile())))
		}
		samples = append(samples, one(name+"_sum", "", ""), one(name+"_count", "", ""))
		return samples
	case dto.MetricType_HISTOGRAM, dto.MetricType_GAUGE_HISTOGRAM:
		if metric.Histogram == nil {
			return nil
		}
		samples := make([]emittedSample, 0, len(metric.Histogram.Bucket)+3)
		infSeen := false
		for _, bucket := range metric.Histogram.Bucket {
			upperBound := bucket.GetUpperBound()
			if math.IsInf(upperBound, 1) {
				infSeen = true
			}
			samples = append(samples, one(name+"_bucket", "le", formatRelabelFloat(upperBound)))
		}
		if !infSeen {
			samples = append(samples, one(name+"_bucket", "le", "+Inf"))
		}
		samples = append(samples, one(name+"_sum", "", ""), one(name+"_count", "", ""))
		return samples
	default:
		return nil
	}
}

func formatRelabelFloat(value float64) string {
	switch {
	case value == 0:
		return "0"
	case math.IsNaN(value):
		return "NaN"
	case math.IsInf(value, 1):
		return "+Inf"
	case math.IsInf(value, -1):
		return "-Inf"
	default:
		return strconv.FormatFloat(value, 'g', -1, 64)
	}
}

func isKnownServiceMonitor(componentName string) bool {
	switch componentName {
	case "kube-apiserver", "etcd", "kube-controller-manager", "openshift-apiserver", "openshift-controller-manager", "openshift-route-controller-manager", "cluster-version-operator", "olm-operator", "catalog-operator", "node-tuning-operator":
		return true
	default:
		return false
	}
}

func getRelabelConfigsForComponent(componentName string, metricsSet metrics.MetricsSet) []prometheusoperatorv1.RelabelConfig {
	switch componentName {
	case "kube-apiserver":
		return metrics.KASRelabelConfigs(metricsSet)
	case "etcd":
		return metrics.EtcdRelabelConfigs(metricsSet)
	case "kube-controller-manager":
		return metrics.KCMRelabelConfigs(metricsSet)
	case "openshift-apiserver":
		return metrics.OpenShiftAPIServerRelabelConfigs(metricsSet)
	case "openshift-controller-manager":
		return metrics.OpenShiftControllerManagerRelabelConfigs(metricsSet)
	case "openshift-route-controller-manager":
		return metrics.OpenShiftRouteControllerManagerRelabelConfigs(metricsSet)
	case "cluster-version-operator":
		return metrics.CVORelabelConfigs(metricsSet)
	case "olm-operator":
		return metrics.OLMRelabelConfigs(metricsSet)
	case "catalog-operator":
		return metrics.CatalogOperatorRelabelConfigs(metricsSet)
	case "node-tuning-operator":
		return metrics.NTORelabelConfigs(metricsSet)
	default:
		return nil
	}
}
