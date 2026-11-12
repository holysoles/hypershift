package metricsproxy

import (
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/gomega"

	"github.com/openshift/hypershift/support/metrics"

	corev1 "k8s.io/api/core/v1"
)

func TestLoadSREMetricsSetConfiguration(t *testing.T) {
	g := NewWithT(t)
	t.Cleanup(func() {
		if err := metrics.LoadSREMetricsSetConfigurationFromConfigMap(&corev1.ConfigMap{Data: map[string]string{metrics.SREConfigurationConfigMapKey: "{}"}}); err != nil {
			t.Errorf("reset SRE metrics config: %v", err)
		}
	})
	configPath := filepath.Join(t.TempDir(), "config")
	config := "kubeAPIServer:\n- action: keep\n  regex: test_metric\n  sourceLabels:\n  - __name__\n"
	g.Expect(os.WriteFile(configPath, []byte(config), 0600)).To(Succeed())
	g.Expect(loadSREMetricsSetConfiguration(configPath)).To(Succeed())
	loaded := metrics.KASRelabelConfigs(metrics.MetricsSetSRE)
	g.Expect(loaded).To(HaveLen(1))
	g.Expect(loaded[0].Regex).To(Equal("test_metric"))

	err := loadSREMetricsSetConfiguration(filepath.Join(t.TempDir(), "missing"))
	g.Expect(os.IsNotExist(err)).To(BeTrue())

	malformedPath := filepath.Join(t.TempDir(), "malformed")
	g.Expect(os.WriteFile(malformedPath, []byte("kubeAPIServer: ["), 0600)).To(Succeed())
	g.Expect(loadSREMetricsSetConfiguration(malformedPath)).To(HaveOccurred())
}
