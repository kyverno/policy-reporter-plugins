package v1

import (
	"github.com/kyverno/policy-reporter/kyverno-plugin/pkg/utils"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
)

type ImageExtractorConfigs map[string][]ImageExtractorConfig

type ImageExtractorConfig struct {
	// Path is the path to the object containing the image field in a custom resource.
	// It should be slash-separated. Each slash-separated key must be a valid YAML key or a wildcard '*'.
	// Wildcard keys are expanded in case of arrays or objects.
	Path string `json:"path"`
	// Value is an optional name of the field within 'path' that points to the image URI.
	// This is useful when a custom 'key' is also defined.
	// +optional
	Value string `json:"value,omitempty"`
	// Name is the entry the image will be available under 'images.<name>' in the context.
	// If this field is not defined, image entries will appear under 'images.custom'.
	// +optional
	Name string `json:"name,omitempty"`
	// Key is an optional name of the field within 'path' that will be used to uniquely identify an image.
	// Note - this field MUST be unique.
	// +optional
	Key string `json:"key,omitempty"`
	// JMESPath is an optional JMESPath expression to apply to the image value.
	// This is useful when the extracted image begins with a prefix like 'docker://'.
	// The 'trim_prefix' function may be used to trim the prefix: trim_prefix(@, 'docker://').
	// Note - Image digest mutation may not be used when applying a JMESPAth to an image.
	// +optional
	JMESPath string `json:"jmesPath,omitempty"`
}

// Rule defines a validation, mutation, or generation control for matching resources.
// Each rules contains a match declaration to select resources, and an optional exclude
// declaration to specify which resources to exclude.
type Rule struct {
	// Name is a label to identify the rule, It must be unique within the policy.
	// +kubebuilder:validation:MaxLength=63
	Name string `json:"name"`

	// Context defines variables and data sources that can be used during rule execution.
	// +optional
	Context []ContextEntry `json:"context,omitempty"`

	// ReportProperties are the additional properties from the rule that will be added to the policy report result
	// +optional
	ReportProperties map[string]string `json:"reportProperties,omitempty"`

	// MatchResources defines when this policy rule should be applied. The match
	// criteria can include resource information (e.g. kind, name, namespace, labels)
	// and admission review request information like the user name or role.
	// At least one kind is required.
	MatchResources MatchResources `json:"match"`

	// ExcludeResources defines when this policy rule should not be applied. The exclude
	// criteria can include resource information (e.g. kind, name, namespace, labels)
	// and admission review request information like the name or role.
	// +optional
	ExcludeResources *MatchResources `json:"exclude,omitempty"`

	// ImageExtractors defines a mapping from kinds to ImageExtractorConfigs.
	// This config is only valid for verifyImages rules.
	// +optional
	ImageExtractors ImageExtractorConfigs `json:"imageExtractors,omitempty"`

	// Preconditions are used to determine if a policy rule should be applied by evaluating a
	// set of conditions. The declaration can contain nested `any` or `all` statements. A direct list
	// of conditions (without `any` or `all` statements is supported for backwards compatibility but
	// will be deprecated in the next major release.
	// See: https://kyverno.io/docs/writing-policies/preconditions/
	// +optional
	// +kubebuilder:validation:Schemaless
	// +kubebuilder:pruning:PreserveUnknownFields
	RawAnyAllConditions *ConditionsWrapper `json:"preconditions,omitempty"`

	// CELPreconditions are used to determine if a policy rule should be applied by evaluating a
	// set of CEL conditions. It can only be used with the validate.cel subrule
	// +optional
	CELPreconditions []admissionregistrationv1.MatchCondition `json:"celPreconditions,omitempty"`

	// Mutation is used to modify matching resources.
	// +optional
	Mutation *Mutation `json:"mutate,omitempty"`

	// Validation is used to validate matching resources.
	// +optional
	Validation *Validation `json:"validate,omitempty"`

	// Generation is used to create new resources.
	// +optional
	Generation *Generation `json:"generate,omitempty"`

	// VerifyImages is used to verify image signatures and mutate them to add a digest
	// +optional
	VerifyImages []ImageVerification `json:"verifyImages,omitempty"`

	// SkipBackgroundRequests bypasses admission requests that are sent by the background controller.
	// The default value is set to "true", it must be set to "false" to apply
	// generate and mutateExisting rules to those requests.
	// +kubebuilder:default=true
	// +kubebuilder:validation:Optional
	SkipBackgroundRequests *bool `json:"skipBackgroundRequests,omitempty"`
}

// HasMutate checks for mutate rule
func (r *Rule) HasMutate() bool {
	return r.Mutation != nil && !utils.DeepEqual(*r.Mutation, Mutation{})
}

// HasValidate checks for validate rule
func (r *Rule) HasValidate() bool {
	return r.Validation != nil && !utils.DeepEqual(*r.Validation, Validation{})
}

// HasGenerate checks for generate rule
func (r *Rule) HasGenerate() bool {
	return r.Generation != nil && !utils.DeepEqual(*r.Generation, Generation{})
}
