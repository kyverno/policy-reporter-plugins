package policyreport

import (
	"fmt"
	"time"

	"golang.org/x/net/context"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kyverno/policy-reporter-plugins/plugins/kyverno/pkg/crd/api/policyreport/v1alpha2"
	pr "github.com/kyverno/policy-reporter-plugins/plugins/kyverno/pkg/crd/client/clientset/versioned/typed/policyreport/v1alpha2"
	"github.com/kyverno/policy-reporter-plugins/plugins/kyverno/pkg/violation"
)

var reportLabels = map[string]string{
	"managed-by": "policy-reporter-kyverno-plugin",
}

type policyReportClient struct {
	client         pr.Wgpolicyk8sV1alpha2Interface
	maxResults     int
	source         string
	keepOnlyLatest bool
}

func (p *policyReportClient) ProcessViolation(ctx context.Context, violation violation.PolicyViolation) error {
	if violation.Resource.Namespace == "" {
		return p.handleClusterScoped(ctx, violation)
	}

	return p.handleNamespaced(ctx, violation, violation.Resource.Namespace)
}

func (p *policyReportClient) handleNamespaced(ctx context.Context, violation violation.PolicyViolation, ns string) error {
	polr, err := p.client.PolicyReports(ns).Get(ctx, GeneratePolicyReportName(ns), v1.GetOptions{})
	if err != nil {
		polr = &v1alpha2.PolicyReport{
			ObjectMeta: v1.ObjectMeta{
				Name:      GeneratePolicyReportName(ns),
				Namespace: ns,
				Labels:    reportLabels,
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
				Name:   ClusterPolicyReport,
				Labels: reportLabels,
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

func NewClient(client pr.Wgpolicyk8sV1alpha2Interface, maxResults int, source string, keepOnlyLatest bool) Client {
	return &policyReportClient{
		client:         client,
		maxResults:     maxResults,
		source:         source,
		keepOnlyLatest: keepOnlyLatest,
	}
}
