package policyreport

import (
	"fmt"
	"time"

	"go.uber.org/zap"
	"golang.org/x/net/context"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kyverno/policy-reporter/kyverno-plugin/pkg/crd/api/policyreport/v1alpha2"
	pr "github.com/kyverno/policy-reporter/kyverno-plugin/pkg/crd/client/clientset/versioned/typed/policyreport/v1alpha2"
	"github.com/kyverno/policy-reporter/kyverno-plugin/pkg/violation"
)

var reportLabels = map[string]string{
	"managed-by": "policy-reporter-kyverno-plugin",
}

type policyReportClient struct {
	client         pr.Wgpolicyk8sV1alpha2Interface
	maxResults     int
	source         string
	keepOnlyLatest bool
	labels         map[string]string
	annotations    map[string]string
}

func (p *policyReportClient) ProcessViolation(ctx context.Context, violation violation.PolicyViolation) error {
	if violation.Resource.Namespace == "" {
		return p.handleClusterScoped(ctx, violation)
	}

	return p.handleNamespaced(ctx, violation, violation.Resource.Namespace)
}

func updateReport[T v1alpha2.ReportInterface](report T, labels, annotations map[string]string) (T, bool) {
	update := false

	rLabels := report.GetLabels()
	if rLabels == nil {
		rLabels = make(map[string]string)
		report.SetLabels(rLabels)
	}

	rAnnotations := report.GetAnnotations()
	if rAnnotations == nil {
		rAnnotations = make(map[string]string)
		report.SetAnnotations(rAnnotations)
	}

	for l, v := range labels {
		if rLabels[l] != v {
			rLabels[l] = v
			update = true
		}
	}

	for l, v := range rLabels {
		if labels[l] != v {
			delete(rLabels, l)
			update = true
		}
	}

	for a, v := range annotations {
		if rAnnotations[a] != v {
			rAnnotations[a] = v
			update = true
		}
	}

	for a, v := range rAnnotations {
		if annotations[a] != v {
			delete(rAnnotations, a)
			update = true
		}
	}

	return report, update
}

func (p *policyReportClient) UpdatePolicyReports(ctx context.Context) error {
	labelSelector := metav1.FormatLabelSelector(&metav1.LabelSelector{MatchLabels: reportLabels})

	list, err := p.client.PolicyReports("").List(ctx, v1.ListOptions{LabelSelector: labelSelector})
	for _, r := range list.Items {
		report, update := updateReport(&r, p.labels, p.annotations)

		if update {
			zap.L().Info("policy report updated", zap.String("name", report.Name))
			p.client.PolicyReports(report.Namespace).Update(ctx, report, v1.UpdateOptions{})
		}
	}

	return err
}

func (p *policyReportClient) UpdateClusterPolicyReports(ctx context.Context) error {
	labelSelector := metav1.FormatLabelSelector(&metav1.LabelSelector{MatchLabels: reportLabels})

	list, err := p.client.ClusterPolicyReports().List(ctx, v1.ListOptions{LabelSelector: labelSelector})
	for _, r := range list.Items {
		report, update := updateReport(&r, p.labels, p.annotations)

		if update {
			p.client.ClusterPolicyReports().Update(ctx, report, v1.UpdateOptions{})
		}
	}

	return err
}

func (p *policyReportClient) handleNamespaced(ctx context.Context, violation violation.PolicyViolation, ns string) error {
	polr, err := p.client.PolicyReports(ns).Get(ctx, GeneratePolicyReportName(ns), v1.GetOptions{})
	if err != nil {
		polr = &v1alpha2.PolicyReport{
			ObjectMeta: v1.ObjectMeta{
				Name:        GeneratePolicyReportName(ns),
				Namespace:   ns,
				Labels:      p.labels,
				Annotations: p.annotations,
			},
		}

		polr, err = p.client.PolicyReports(ns).Create(ctx, polr, v1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("failed to create PolicyReport in namespace %s: %s", ns, err)
		}
	}

	if polr.Results == nil {
		polr.Results = []v1alpha2.PolicyReportResult{}
	}
	if len(polr.Results) >= p.maxResults {
		startIndex := len(polr.Results) - p.maxResults + 1

		polr.Summary.Fail--
		polr.Results = polr.Results[startIndex:]
	}

	if violation.Updated && p.keepOnlyLatest {
		index := prevIndex(polr.Results, violation)
		if index >= 0 {
			polr.Results = append(polr.Results[:index], polr.Results[index+1:]...)
			polr.Summary.Fail--
		}
	}

	result := buildResult(violation, p.source)
	for _, item := range polr.Results {
		if item.Properties["resultID"] == result.Properties["resultID"] {
			return nil
		}
	}

	polr.Summary.Fail++
	polr.Results = append(polr.Results, result)

	_, err = p.client.PolicyReports(ns).Update(ctx, polr, v1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update PolicyReport in namespace %s: %s", ns, err)
	}

	return nil
}

func (p *policyReportClient) handleClusterScoped(ctx context.Context, violation violation.PolicyViolation) error {
	polr, err := p.client.ClusterPolicyReports().Get(ctx, ClusterPolicyReport, v1.GetOptions{})
	if err != nil {
		polr = &v1alpha2.ClusterPolicyReport{
			ObjectMeta: v1.ObjectMeta{
				Name:        ClusterPolicyReport,
				Labels:      p.labels,
				Annotations: p.annotations,
			},
		}

		polr, err = p.client.ClusterPolicyReports().Create(ctx, polr, v1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("failed to create ClusterPolicyReport: %s", err)
		}
	}

	if polr.Results == nil {
		polr.Results = []v1alpha2.PolicyReportResult{}
	}
	if len(polr.Results) >= p.maxResults {
		startIndex := len(polr.Results) - p.maxResults + 1

		polr.Summary.Fail--
		polr.Results = polr.Results[startIndex:]
	}

	if violation.Updated && p.keepOnlyLatest {
		index := prevIndex(polr.Results, violation)
		if index >= 0 {
			polr.Results = append(polr.Results[:index], polr.Results[index+1:]...)
			polr.Summary.Fail--
		}
	}

	result := buildResult(violation, p.source)
	for _, item := range polr.Results {
		if item.Properties["resultID"] == result.Properties["resultID"] {
			return nil
		}
	}

	polr.Summary.Fail++
	polr.Results = append(polr.Results, result)

	_, err = p.client.ClusterPolicyReports().Update(ctx, polr, v1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update ClusterPolicyReport: %s", err)
	}

	return nil
}

func buildResult(violation violation.PolicyViolation, source string) v1alpha2.PolicyReportResult {
	return v1alpha2.PolicyReportResult{
		Source:   source,
		Policy:   violation.Policy.Name,
		Rule:     violation.Policy.Rule,
		Category: violation.Policy.Category,
		Severity: v1alpha2.PolicySeverity(violation.Policy.Severity),
		Message:  violation.Policy.Message,
		Result:   "fail",
		Resources: []corev1.ObjectReference{
			{
				Kind:      violation.Resource.Kind,
				Namespace: violation.Resource.Namespace,
				Name:      violation.Resource.Name,
			},
		},
		Timestamp: v1.Timestamp{Seconds: violation.Timestamp.Unix()},
		Properties: map[string]string{
			"eventName": violation.Event.Name,
			"resultID":  GeneratePolicyReportResultID(violation.Event.UID, violation.Timestamp),
			"time":      violation.Timestamp.Format(time.RFC3339),
		},
	}
}

func prevIndex(results []v1alpha2.PolicyReportResult, violation violation.PolicyViolation) int {
	for index, result := range results {
		if result.Properties["eventName"] == violation.Event.Name {
			return index
		}
	}

	return -1
}

func NewClient(client pr.Wgpolicyk8sV1alpha2Interface, maxResults int, source string, keepOnlyLatest bool, labels, annotations map[string]string) Client {
	for l, v := range reportLabels {
		labels[l] = v
	}

	return &policyReportClient{
		client:         client,
		maxResults:     maxResults,
		source:         source,
		keepOnlyLatest: keepOnlyLatest,
		labels:         labels,
		annotations:    annotations,
	}
}
