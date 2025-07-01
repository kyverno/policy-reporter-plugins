package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=clusterpolicies,scope="Cluster",shortName=cpol,categories=kyverno
// +kubebuilder:printcolumn:name="ADMISSION",type=boolean,JSONPath=".spec.admission"
// +kubebuilder:printcolumn:name="BACKGROUND",type=boolean,JSONPath=".spec.background"
// +kubebuilder:printcolumn:name="READY",type=string,JSONPath=`.status.conditions[?(@.type == "Ready")].status`
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:printcolumn:name="FAILURE POLICY",type=string,JSONPath=".spec.failurePolicy",priority=1
// +kubebuilder:printcolumn:name="VALIDATE",type=integer,JSONPath=`.status.rulecount.validate`,priority=1
// +kubebuilder:printcolumn:name="MUTATE",type=integer,JSONPath=`.status.rulecount.mutate`,priority=1
// +kubebuilder:printcolumn:name="GENERATE",type=integer,JSONPath=`.status.rulecount.generate`,priority=1
// +kubebuilder:printcolumn:name="VERIFY IMAGES",type=integer,JSONPath=`.status.rulecount.verifyimages`,priority=1
// +kubebuilder:printcolumn:name="MESSAGE",type=string,JSONPath=`.status.conditions[?(@.type == "Ready")].message`
// +kubebuilder:storageversion

// ClusterPolicy declares validation, mutation, and generation behaviors for matching resources.
type ClusterPolicy struct {
	metav1.TypeMeta   `json:",inline,omitempty"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec declares policy behaviors.
	Spec Spec `json:"spec"`

	// Status contains policy runtime data.
	// +optional
	Status PolicyStatus `json:"status,omitempty"`
}

// GetSpec returns the policy spec
func (p *ClusterPolicy) GetSpec() *Spec {
	return &p.Spec
}

// GetStatus returns the policy status
func (p *ClusterPolicy) GetStatus() *PolicyStatus {
	return &p.Status
}

// IsNamespaced indicates if the policy is namespace scoped
func (p *ClusterPolicy) IsNamespaced() bool {
	return false
}

// IsReady indicates if the policy is ready to serve the admission request
func (p *ClusterPolicy) IsReady() bool {
	return p.Status.IsReady()
}

func (p *ClusterPolicy) GetKind() string {
	return "ClusterPolicy"
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ClusterPolicyList is a list of ClusterPolicy instances.
type ClusterPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []ClusterPolicy `json:"items"`
}
