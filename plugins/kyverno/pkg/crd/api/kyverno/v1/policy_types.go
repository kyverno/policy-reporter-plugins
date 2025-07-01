package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
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
// +kubebuilder:resource:shortName=pol,categories=kyverno
// +kubebuilder:storageversion

// Policy declares validation, mutation, and generation behaviors for matching resources.
// See: https://kyverno.io/docs/writing-policies/ for more information.
type Policy struct {
	metav1.TypeMeta   `json:",inline,omitempty"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec defines policy behaviors and contains one or more rules.
	Spec Spec `json:"spec"`

	// +optional
	// Deprecated. Policy metrics are available via the metrics endpoint
	Status PolicyStatus `json:"status,omitempty"`
}

// GetSpec returns the policy spec
func (p *Policy) GetSpec() *Spec {
	return &p.Spec
}

// GetStatus returns the policy status
func (p *Policy) GetStatus() *PolicyStatus {
	return &p.Status
}

func (p *Policy) GetKind() string {
	return "Policy"
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// PolicyList is a list of Policy instances.
type PolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []Policy `json:"items"`
}
