package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ValidationFailureAction defines the policy validation failure action
type ValidationFailureAction string

// Policy Reporting Modes
const (
	// auditOld doesn't block the request on failure
	// DEPRECATED: use Audit instead
	auditOld ValidationFailureAction = "audit"
	// enforceOld blocks the request on failure
	// DEPRECATED: use Enforce instead
	enforceOld ValidationFailureAction = "enforce"
	// Enforce blocks the request on failure
	Enforce ValidationFailureAction = "Enforce"
	// Audit doesn't block the request on failure
	Audit ValidationFailureAction = "Audit"
)

func (a ValidationFailureAction) Enforce() bool {
	return a == Enforce || a == enforceOld
}

func (a ValidationFailureAction) Audit() bool {
	return !a.Enforce()
}

func (a ValidationFailureAction) IsValid() bool {
	return a == enforceOld || a == auditOld || a == Enforce || a == Audit
}

type ValidationFailureActionOverride struct {
	// +kubebuilder:validation:Enum=audit;enforce;Audit;Enforce
	Action            ValidationFailureAction `json:"action,omitempty"`
	Namespaces        []string                `json:"namespaces,omitempty"`
	NamespaceSelector *metav1.LabelSelector   `json:"namespaceSelector,omitempty"`
}

// Spec contains a list of Rule instances and other policy controls.
type Spec struct {
	// Rules is a list of Rule instances. A Policy contains multiple rules and
	// each rule can validate, mutate, or generate resources.
	Rules []Rule `json:"rules,omitempty"`

	// ApplyRules controls how rules in a policy are applied. Rule are processed in
	// the order of declaration. When set to `One` processing stops after a rule has
	// been applied i.e. the rule matches and results in a pass, fail, or error. When
	// set to `All` all rules in the policy are processed. The default is `All`.
	// +optional
	ApplyRules *ApplyRulesType `json:"applyRules,omitempty"`

	// Deprecated, use failurePolicy under the webhookConfiguration instead.
	FailurePolicy *FailurePolicyType `json:"failurePolicy,omitempty"`

	// Deprecated, use validationFailureAction under the validate rule instead.
	// +kubebuilder:validation:Enum=audit;enforce;Audit;Enforce
	// +kubebuilder:default=Audit
	ValidationFailureAction ValidationFailureAction `json:"validationFailureAction,omitempty"`

	// Deprecated, use validationFailureActionOverrides under the validate rule instead.
	ValidationFailureActionOverrides []ValidationFailureActionOverride `json:"validationFailureActionOverrides,omitempty"`

	// EmitWarning enables API response warnings for mutate policy rules or validate policy rules with validationFailureAction set to Audit.
	// Enabling this option will extend admission request processing times. The default value is "false".
	// +optional
	// +kubebuilder:default=false
	EmitWarning *bool `json:"emitWarning,omitempty"`

	// Admission controls if rules are applied during admission.
	// Optional. Default value is "true".
	// +optional
	// +kubebuilder:default=true
	Admission *bool `json:"admission,omitempty"`

	// Background controls if rules are applied to existing resources during a background scan.
	// Optional. Default value is "true". The value must be set to "false" if the policy rule
	// uses variables that are only available in the admission review request (e.g. user name).
	// +optional
	// +kubebuilder:default=true
	Background *bool `json:"background,omitempty"`

	// Deprecated.
	SchemaValidation *bool `json:"schemaValidation,omitempty"`

	// Deprecated, use webhookTimeoutSeconds under webhookConfiguration instead.
	WebhookTimeoutSeconds *int32 `json:"webhookTimeoutSeconds,omitempty"`

	// Deprecated, use mutateExistingOnPolicyUpdate under the mutate rule instead
	// +optional
	MutateExistingOnPolicyUpdate bool `json:"mutateExistingOnPolicyUpdate,omitempty"`

	// Deprecated, use generateExisting instead
	// +optional
	GenerateExistingOnPolicyUpdate *bool `json:"generateExistingOnPolicyUpdate,omitempty"`

	// Deprecated, use generateExisting under the generate rule instead
	// +optional
	GenerateExisting bool `json:"generateExisting,omitempty"`

	// UseServerSideApply controls whether to use server-side apply for generate rules
	// If is set to "true" create & update for generate rules will use apply instead of create/update.
	// Defaults to "false" if not specified.
	// +optional
	UseServerSideApply bool `json:"useServerSideApply,omitempty"`

	// WebhookConfiguration specifies the custom configuration for Kubernetes admission webhookconfiguration.
	// +optional
	WebhookConfiguration *WebhookConfiguration `json:"webhookConfiguration,omitempty"`
}

// HasMutate checks for mutate rule types
func (s *Spec) HasMutate() bool {
	for _, rule := range s.Rules {
		if rule.HasMutate() {
			return true
		}
	}
	return false
}

// HasValidate checks for validate rule types
func (s *Spec) HasValidate() bool {
	for _, rule := range s.Rules {
		if rule.HasValidate() {
			return true
		}
	}
	return false
}
