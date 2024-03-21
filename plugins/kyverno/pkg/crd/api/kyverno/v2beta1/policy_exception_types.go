/*
Copyright 2022 The Kubernetes authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package v2beta1

import (
	kyvernov1 "github.com/kyverno/policy-reporter/kyverno-plugin/pkg/crd/api/kyverno/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:shortName=polex,categories=kyverno
// +kubebuilder:storageversion

// PolicyException declares resources to be excluded from specified policies.
type PolicyException struct {
	metav1.TypeMeta   `json:",inline,omitempty" yaml:",inline,omitempty"`
	metav1.ObjectMeta `json:"metadata,omitempty" yaml:"metadata,omitempty"`

	// Spec declares policy exception behaviors.
	Spec PolicyExceptionSpec `json:"spec" yaml:"spec"`
}

// PolicyExceptionSpec stores policy exception spec
type PolicyExceptionSpec struct {
	// Background controls if exceptions are applied to existing policies during a background scan.
	// Optional. Default value is "true". The value must be set to "false" if the policy rule
	// uses variables that are only available in the admission review request (e.g. user name).
	Background *bool `json:"background,omitempty" yaml:"background,omitempty"`

	// Match defines match clause used to check if a resource applies to the exception
	Match MatchResources `json:"match" yaml:"match"`

	// Conditions are used to determine if a resource applies to the exception by evaluating a
	// set of conditions. The declaration can contain nested `any` or `all` statements.
	// +optional
	Conditions *AnyAllConditions `json:"conditions,omitempty"`

	// Exceptions is a list policy/rules to be excluded
	Exceptions []Exception `json:"exceptions" yaml:"exceptions"`

	// PodSecurity specifies the Pod Security Standard controls to be excluded.
	// Applicable only to policies that have validate.podSecurity subrule.
	// +optional
	PodSecurity []kyvernov1.PodSecurityStandard `json:"podSecurity,omitempty" yaml:"podSecurity,omitempty"`
}

// Exception stores infos about a policy and rules
type Exception struct {
	// PolicyName identifies the policy to which the exception is applied.
	// The policy name uses the format <namespace>/<name> unless it
	// references a ClusterPolicy.
	PolicyName string `json:"policyName" yaml:"policyName"`

	// RuleNames identifies the rules to which the exception is applied.
	RuleNames []string `json:"ruleNames" yaml:"ruleNames"`
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// PolicyExceptionList is a list of Policy Exceptions
type PolicyExceptionList struct {
	metav1.TypeMeta `json:",inline" yaml:",inline"`
	metav1.ListMeta `json:"metadata" yaml:"metadata"`
	Items           []PolicyException `json:"items" yaml:"items"`
}
