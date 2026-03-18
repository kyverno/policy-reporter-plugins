package v2

import (
	kyvernov1 "github.com/kyverno/policy-reporter/kyverno-plugin/pkg/crd/api/kyverno/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:shortName=gctxentry,categories=kyverno,scope="Cluster"
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:printcolumn:name="REFRESH INTERVAL",type="string",JSONPath=".spec.apiCall.refreshInterval"
// +kubebuilder:printcolumn:name="LAST REFRESH",type="date",JSONPath=".status.lastRefreshTime"

// GlobalContextEntry declares resources to be cached.
type GlobalContextEntry struct {
	metav1.TypeMeta   `json:",inline,omitempty"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec declares policy exception behaviors.
	Spec GlobalContextEntrySpec `json:"spec"`

	// Status contains globalcontextentry runtime data.
	// +optional
	Status GlobalContextEntryStatus `json:"status,omitempty"`
}

// GlobalContextEntrySpec stores policy exception spec
// +kubebuilder:oneOf:={required:{kubernetesResource}}
// +kubebuilder:oneOf:={required:{apiCall}}
type GlobalContextEntrySpec struct {
	// Stores a list of Kubernetes resources which will be cached.
	// Mutually exclusive with APICall.
	// +kubebuilder:validation:Optional
	KubernetesResource *KubernetesResource `json:"kubernetesResource,omitempty"`

	// Stores results from an API call which will be cached.
	// Mutually exclusive with KubernetesResource.
	// This can be used to make calls to external (non-Kubernetes API server) services.
	// It can also be used to make calls to the Kubernetes API server in such cases:
	// 1. A POST is needed to create a resource.
	// 2. Finer-grained control is needed. Example: To restrict the number of resources cached.
	// +kubebuilder:validation:Optional
	APICall *ExternalAPICall `json:"apiCall,omitempty"`

	// Projections defines the list of JMESPath expressions to extract values from the cached resource.
	// +kubebuilder:validation:Optional
	Projections []GlobalContextEntryProjection `json:"projections,omitempty"`
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// GlobalContextEntryList is a list of Cached Context Entries
type GlobalContextEntryList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []GlobalContextEntry `json:"items"`
}

// KubernetesResource stores infos about kubernetes resource that should be cached
type KubernetesResource struct {
	// Group defines the group of the resource.
	// +kubebuilder:validation:Optional
	Group string `json:"group,omitempty"`
	// Version defines the version of the resource.
	// +kubebuilder:validation:Required
	Version string `json:"version"`
	// Resource defines the type of the resource.
	// Requires the pluralized form of the resource kind in lowercase. (Ex., "deployments")
	// +kubebuilder:validation:Required
	Resource string `json:"resource"`
	// Namespace defines the namespace of the resource. Leave empty for cluster scoped resources.
	// If left empty for namespaced resources, all resources from all namespaces will be cached.
	// +kubebuilder:validation:Optional
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

type ExternalAPICall struct {
	kyvernov1.APICall `json:",inline,omitempty"`
	// RefreshInterval defines the interval in duration at which to poll the APICall.
	// The duration is a sequence of decimal numbers, each with optional fraction and a unit suffix,
	// such as "300ms", "1.5h" or "2h45m". Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".
	// +kubebuilder:validation:Format=duration
	// +kubebuilder:default=`10m`
	RefreshInterval *metav1.Duration `json:"refreshInterval,omitempty"`
	// RetryLimit defines the number of times the APICall should be retried in case of failure.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:default=3
	// +kubebuilder:validation:Optional
	// +optional
	RetryLimit int `json:"retryLimit,omitempty"`
}

type GlobalContextEntryProjection struct {
	// Name is the name to use for the extracted value in the context.
	// +kubebuilder:validation:Required
	Name string `json:"name"`
	// JMESPath is the JMESPath expression to extract the value from the cached resource.
	// +kubebuilder:validation:Required
	JMESPath string `json:"jmesPath"`
}
