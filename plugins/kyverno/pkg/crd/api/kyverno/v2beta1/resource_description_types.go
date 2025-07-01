package v2beta1

import (
	kyvernov1 "github.com/kyverno/policy-reporter/kyverno-plugin/pkg/crd/api/kyverno/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ResourceDescription contains criteria used to match resources.
type ResourceDescription struct {
	// Kinds is a list of resource kinds.
	// +optional
	Kinds []string `json:"kinds,omitempty"`

	// Names are the names of the resources. Each name supports wildcard characters
	// "*" (matches zero or many characters) and "?" (at least one character).
	// +optional
	Names []string `json:"names,omitempty"`

	// Namespaces is a list of namespaces names. Each name supports wildcard characters
	// "*" (matches zero or many characters) and "?" (at least one character).
	// +optional
	Namespaces []string `json:"namespaces,omitempty"`

	// Annotations is a  map of annotations (key-value pairs of type string). Annotation keys
	// and values support the wildcard characters "*" (matches zero or many characters) and
	// "?" (matches at least one character).
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// Selector is a label selector. Label keys and values in `matchLabels` support the wildcard
	// characters `*` (matches zero or many characters) and `?` (matches one character).
	// Wildcards allows writing label selectors like ["storage.k8s.io/*": "*"]. Note that
	// using ["*" : "*"] matches any key and value but does not match an empty label set.
	// +optional
	Selector *metav1.LabelSelector `json:"selector,omitempty"`

	// NamespaceSelector is a label selector for the resource namespace. Label keys and values
	// in `matchLabels` support the wildcard characters `*` (matches zero or many characters)
	// and `?` (matches one character).Wildcards allows writing label selectors like
	// ["storage.k8s.io/*": "*"]. Note that using ["*" : "*"] matches any key and value but
	// does not match an empty label set.
	// +optional
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`

	// Operations can contain values ["CREATE, "UPDATE", "CONNECT", "DELETE"], which are used to match a specific action.
	// +optional
	Operations []kyvernov1.AdmissionOperation `json:"operations,omitempty"`
}
