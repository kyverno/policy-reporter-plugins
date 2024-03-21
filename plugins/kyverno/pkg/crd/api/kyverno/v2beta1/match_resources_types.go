package v2beta1

import (
	kyvernov1 "github.com/kyverno/policy-reporter/kyverno-plugin/pkg/crd/api/kyverno/v1"
)

// MatchResources is used to specify resource and admission review request data for
// which a policy rule is applicable.
type MatchResources struct {
	// Any allows specifying resources which will be ORed
	// +optional
	Any kyvernov1.ResourceFilters `json:"any,omitempty" yaml:"any,omitempty"`

	// All allows specifying resources which will be ANDed
	// +optional
	All kyvernov1.ResourceFilters `json:"all,omitempty" yaml:"all,omitempty"`
}
