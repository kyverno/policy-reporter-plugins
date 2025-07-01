package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

type ResourceSpec struct {
	// APIVersion specifies resource apiVersion.
	// +optional
	APIVersion string `json:"apiVersion,omitempty"`
	// Kind specifies resource kind.
	Kind string `json:"kind,omitempty"`
	// Namespace specifies resource namespace.
	// +optional
	Namespace string `json:"namespace,omitempty"`
	// Name specifies the resource name.
	// +optional
	Name string `json:"name,omitempty"`
	// UID specifies the resource uid.
	// +optional
	UID types.UID `json:"uid,omitempty"`
}

type TargetSelector struct {
	// ResourceSpec contains the target resources to load when mutating existing resources.
	ResourceSpec `json:",omitempty"`
	// Selector allows you to select target resources with their labels.
	// +optional
	Selector *metav1.LabelSelector `json:"selector,omitempty"`
}

// TargetResourceSpec defines targets for mutating existing resources.
type TargetResourceSpec struct {
	// TargetSelector contains the ResourceSpec and a label selector to support selecting with labels.
	TargetSelector `json:",omitempty"`

	// Context defines variables and data sources that can be used during rule execution.
	// +optional
	Context []ContextEntry `json:"context,omitempty"`

	// Preconditions are used to determine if a policy rule should be applied by evaluating a
	// set of conditions. The declaration can contain nested `any` or `all` statements. A direct list
	// of conditions (without `any` or `all` statements is supported for backwards compatibility but
	// will be deprecated in the next major release.
	// See: https://kyverno.io/docs/writing-policies/preconditions/
	// +optional
	// +kubebuilder:validation:Schemaless
	// +kubebuilder:pruning:PreserveUnknownFields
	RawAnyAllConditions *ConditionsWrapper `json:"preconditions,omitempty"`
}
