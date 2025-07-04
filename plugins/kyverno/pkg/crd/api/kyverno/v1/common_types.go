package v1

import (
	kjson "github.com/kyverno/kyverno-json/pkg/apis/policy/v1alpha1"
	"github.com/kyverno/policy-reporter/kyverno-plugin/pkg/crd/api/kyverno"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/pod-security-admission/api"
)

// AssertionTree defines a kyverno-json assertion tree.
type AssertionTree = kjson.Any

// FailurePolicyType specifies a failure policy that defines how unrecognized errors from the admission endpoint are handled.
// +kubebuilder:validation:Enum=Ignore;Fail
type FailurePolicyType string

const (
	// Ignore means that an error calling the webhook is ignored.
	Ignore FailurePolicyType = "Ignore"
	// Fail means that an error calling the webhook causes the admission to fail.
	Fail FailurePolicyType = "Fail"
)

// ApplyRulesType controls whether processing stops after one rule is applied or all rules are applied.
// +kubebuilder:validation:Enum=All;One
type ApplyRulesType string

const (
	// ApplyAll applies all rules in a policy that match.
	ApplyAll ApplyRulesType = "All"
	// ApplyOne applies only the first matching rule in the policy.
	ApplyOne ApplyRulesType = "One"
)

// ForeachOrder specifies the iteration order in foreach statements.
// +kubebuilder:validation:Enum=Ascending;Descending
type ForeachOrder string

const (
	// Ascending means iterating from first to last element.
	Ascending ForeachOrder = "Ascending"
	// Descending means iterating from last to first element.
	Descending ForeachOrder = "Descending"
)

// WebhookConfiguration specifies the configuration for Kubernetes admission webhookconfiguration.
type WebhookConfiguration struct {
	// FailurePolicy defines how unexpected policy errors and webhook response timeout errors are handled.
	// Rules within the same policy share the same failure behavior.
	// This field should not be accessed directly, instead `GetFailurePolicy()` should be used.
	// Allowed values are Ignore or Fail. Defaults to Fail.
	// +optional
	FailurePolicy *FailurePolicyType `json:"failurePolicy,omitempty"`

	// TimeoutSeconds specifies the maximum time in seconds allowed to apply this policy.
	// After the configured time expires, the admission request may fail, or may simply ignore the policy results,
	// based on the failure policy. The default timeout is 10s, the value must be between 1 and 30 seconds.
	TimeoutSeconds *int32 `json:"timeoutSeconds,omitempty"`

	// MatchCondition configures admission webhook matchConditions.
	// Requires Kubernetes 1.27 or later.
	// +optional
	MatchConditions []admissionregistrationv1.MatchCondition `json:"matchConditions,omitempty"`
}

// AnyAllConditions consists of conditions wrapped denoting a logical criteria to be fulfilled.
// AnyConditions get fulfilled when at least one of its sub-conditions passes.
// AllConditions get fulfilled only when all of its sub-conditions pass.
type AnyAllConditions struct {
	// AnyConditions enable variable-based conditional rule execution. This is useful for
	// finer control of when an rule is applied. A condition can reference object data
	// using JMESPath notation.
	// Here, at least one of the conditions need to pass
	// +optional
	AnyConditions []Condition `json:"any,omitempty"`

	// AllConditions enable variable-based conditional rule execution. This is useful for
	// finer control of when an rule is applied. A condition can reference object data
	// using JMESPath notation.
	// Here, all of the conditions need to pass
	// +optional
	AllConditions []Condition `json:"all,omitempty"`
}

// ContextEntry adds variables and data sources to a rule Context. Either a
// ConfigMap reference or a APILookup must be provided.
// +kubebuilder:oneOf:={required:{configMap}}
// +kubebuilder:oneOf:={required:{apiCall}}
// +kubebuilder:oneOf:={required:{imageRegistry}}
// +kubebuilder:oneOf:={required:{variable}}
// +kubebuilder:oneOf:={required:{globalReference}}
type ContextEntry struct {
	// Name is the variable name.
	Name string `json:"name"`

	// ConfigMap is the ConfigMap reference.
	ConfigMap *ConfigMapReference `json:"configMap,omitempty"`

	// APICall is an HTTP request to the Kubernetes API server, or other JSON web service.
	// The data returned is stored in the context with the name for the context entry.
	APICall *ContextAPICall `json:"apiCall,omitempty"`

	// ImageRegistry defines requests to an OCI/Docker V2 registry to fetch image
	// details.
	ImageRegistry *ImageRegistry `json:"imageRegistry,omitempty"`

	// Variable defines an arbitrary JMESPath context variable that can be defined inline.
	Variable *Variable `json:"variable,omitempty"`

	// GlobalContextEntryReference is a reference to a cached global context entry.
	GlobalReference *GlobalContextEntryReference `json:"globalReference,omitempty"`
}

// Variable defines an arbitrary JMESPath context variable that can be defined inline.
type Variable struct {
	// Value is any arbitrary JSON object representable in YAML or JSON form.
	// +optional
	// +kubebuilder:validation:Schemaless
	// +kubebuilder:pruning:PreserveUnknownFields
	Value *kyverno.Any `json:"value,omitempty"`

	// JMESPath is an optional JMESPath Expression that can be used to
	// transform the variable.
	// +optional
	JMESPath string `json:"jmesPath,omitempty"`

	// Default is an optional arbitrary JSON object that the variable may take if the JMESPath
	// expression evaluates to nil
	// +optional
	// +kubebuilder:validation:Schemaless
	// +kubebuilder:pruning:PreserveUnknownFields
	Default *kyverno.Any `json:"default,omitempty"`
}

// ImageRegistry defines requests to an OCI/Docker V2 registry to fetch image
// details.
type ImageRegistry struct {
	// Reference is image reference to a container image in the registry.
	// Example: ghcr.io/kyverno/kyverno:latest
	Reference string `json:"reference"`

	// JMESPath is an optional JSON Match Expression that can be used to
	// transform the ImageData struct returned as a result of processing
	// the image reference.
	// +optional
	JMESPath string `json:"jmesPath,omitempty"`

	// ImageRegistryCredentials provides credentials that will be used for authentication with registry
	// +kubebuilder:validation:Optional
	ImageRegistryCredentials *ImageRegistryCredentials `json:"imageRegistryCredentials,omitempty"`
}

// ConfigMapReference refers to a ConfigMap
type ConfigMapReference struct {
	// Name is the ConfigMap name.
	Name string `json:"name"`

	// Namespace is the ConfigMap namespace.
	Namespace string `json:"namespace,omitempty"`
}

type APICall struct {
	// URLPath is the URL path to be used in the HTTP GET or POST request to the
	// Kubernetes API server (e.g. "/api/v1/namespaces" or  "/apis/apps/v1/deployments").
	// The format required is the same format used by the `kubectl get --raw` command.
	// See https://kyverno.io/docs/writing-policies/external-data-sources/#variables-from-kubernetes-api-server-calls
	// for details.
	// It's mutually exclusive with the Service field.
	// +kubebuilder:validation:Optional
	URLPath string `json:"urlPath"`

	// Method is the HTTP request type (GET or POST). Defaults to GET.
	// +kubebuilder:default=GET
	Method Method `json:"method,omitempty"`

	// The data object specifies the POST data sent to the server.
	// Only applicable when the method field is set to POST.
	// +kubebuilder:validation:Optional
	Data []RequestData `json:"data,omitempty"`

	// Service is an API call to a JSON web service.
	// This is used for non-Kubernetes API server calls.
	// It's mutually exclusive with the URLPath field.
	// +kubebuilder:validation:Optional
	Service *ServiceCall `json:"service,omitempty"`
}

type ContextAPICall struct {
	APICall `json:",inline"`

	// Default is an optional arbitrary JSON object that the context
	// value is set to, if the apiCall returns error.
	// +optional
	Default *apiextv1.JSON `json:"default,omitempty"`

	// JMESPath is an optional JSON Match Expression that can be used to
	// transform the JSON response returned from the server. For example
	// a JMESPath of "items | length(@)" applied to the API server response
	// for the URLPath "/apis/apps/v1/deployments" will return the total count
	// of deployments across all namespaces.
	// +kubebuilder:validation:Optional
	JMESPath string `json:"jmesPath,omitempty"`
}

type GlobalContextEntryReference struct {
	// Name of the global context entry
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// JMESPath is an optional JSON Match Expression that can be used to
	// transform the JSON response returned from the server. For example
	// a JMESPath of "items | length(@)" applied to the API server response
	// for the URLPath "/apis/apps/v1/deployments" will return the total count
	// of deployments across all namespaces.
	// +kubebuilder:validation:Optional
	JMESPath string `json:"jmesPath,omitempty"`
}

type ServiceCall struct {
	// URL is the JSON web service URL. A typical form is
	// `https://{service}.{namespace}:{port}/{path}`.
	URL string `json:"url"`

	// Headers is a list of optional HTTP headers to be included in the request.
	Headers []HTTPHeader `json:"headers,omitempty"`

	// CABundle is a PEM encoded CA bundle which will be used to validate
	// the server certificate.
	// +kubebuilder:validation:Optional
	CABundle string `json:"caBundle"`
}

// Method is a HTTP request type.
// +kubebuilder:validation:Enum=GET;POST
type Method string

// RequestData contains the HTTP POST data
type RequestData struct {
	// Key is a unique identifier for the data value
	Key string `json:"key"`

	// Value is the data value
	Value *apiextv1.JSON `json:"value"`
}

type HTTPHeader struct {
	// Key is the header key
	Key string `json:"key"`
	// Value is the header value
	Value string `json:"value"`
}

// Condition defines variable-based conditional criteria for rule execution.
type Condition struct {
	// Key is the context entry (using JMESPath) for conditional rule evaluation.
	RawKey *apiextv1.JSON `json:"key,omitempty"`

	// Operator is the conditional operation to perform. Valid operators are:
	// Equals, NotEquals, In, AnyIn, AllIn, NotIn, AnyNotIn, AllNotIn, GreaterThanOrEquals,
	// GreaterThan, LessThanOrEquals, LessThan, DurationGreaterThanOrEquals, DurationGreaterThan,
	// DurationLessThanOrEquals, DurationLessThan
	Operator ConditionOperator `json:"operator,omitempty"`

	// Value is the conditional value, or set of values. The values can be fixed set
	// or can be variables declared using JMESPath.
	// +optional
	RawValue *apiextv1.JSON `json:"value,omitempty"`

	// Message is an optional display message
	Message string `json:"message,omitempty"`
}

// ConditionOperator is the operation performed on condition key and value.
// +kubebuilder:validation:Enum=Equals;NotEquals;In;AnyIn;AllIn;NotIn;AnyNotIn;AllNotIn;GreaterThanOrEquals;GreaterThan;LessThanOrEquals;LessThan;DurationGreaterThanOrEquals;DurationGreaterThan;DurationLessThanOrEquals;DurationLessThan
type ConditionOperator string

// ConditionOperators stores all the valid ConditionOperator types as key-value pairs.
//
// "Equal" evaluates if the key is equal to the value. (Deprecated; Use Equals instead)
// "Equals" evaluates if the key is equal to the value.
// "NotEqual" evaluates if the key is not equal to the value. (Deprecated; Use NotEquals instead)
// "NotEquals" evaluates if the key is not equal to the value.
// "In" evaluates if the key is contained in the set of values.
// "AnyIn" evaluates if any of the keys are contained in the set of values.
// "AllIn" evaluates if all the keys are contained in the set of values.
// "NotIn" evaluates if the key is not contained in the set of values.
// "AnyNotIn" evaluates if any of the keys are not contained in the set of values.
// "AllNotIn" evaluates if all the keys are not contained in the set of values.
// "GreaterThanOrEquals" evaluates if the key (numeric) is greater than or equal to the value (numeric).
// "GreaterThan" evaluates if the key (numeric) is greater than the value (numeric).
// "LessThanOrEquals" evaluates if the key (numeric) is less than or equal to the value (numeric).
// "LessThan" evaluates if the key (numeric) is less than the value (numeric).
// "DurationGreaterThanOrEquals" evaluates if the key (duration) is greater than or equal to the value (duration)
// "DurationGreaterThan" evaluates if the key (duration) is greater than the value (duration)
// "DurationLessThanOrEquals" evaluates if the key (duration) is less than or equal to the value (duration)
// "DurationLessThan" evaluates if the key (duration) is greater than the value (duration)
var ConditionOperators = map[string]ConditionOperator{
	"Equal":                       ConditionOperator("Equal"),
	"Equals":                      ConditionOperator("Equals"),
	"NotEqual":                    ConditionOperator("NotEqual"),
	"NotEquals":                   ConditionOperator("NotEquals"),
	"In":                          ConditionOperator("In"),
	"AnyIn":                       ConditionOperator("AnyIn"),
	"AllIn":                       ConditionOperator("AllIn"),
	"NotIn":                       ConditionOperator("NotIn"),
	"AnyNotIn":                    ConditionOperator("AnyNotIn"),
	"AllNotIn":                    ConditionOperator("AllNotIn"),
	"GreaterThanOrEquals":         ConditionOperator("GreaterThanOrEquals"),
	"GreaterThan":                 ConditionOperator("GreaterThan"),
	"LessThanOrEquals":            ConditionOperator("LessThanOrEquals"),
	"LessThan":                    ConditionOperator("LessThan"),
	"DurationGreaterThanOrEquals": ConditionOperator("DurationGreaterThanOrEquals"),
	"DurationGreaterThan":         ConditionOperator("DurationGreaterThan"),
	"DurationLessThanOrEquals":    ConditionOperator("DurationLessThanOrEquals"),
	"DurationLessThan":            ConditionOperator("DurationLessThan"),
}

// ResourceFilters is a slice of ResourceFilter
type ResourceFilters []ResourceFilter

// ResourceFilter allow users to "AND" or "OR" between resources
type ResourceFilter struct {
	// UserInfo contains information about the user performing the operation.
	// +optional
	UserInfo `json:",omitempty"`

	// ResourceDescription contains information about the resource being created or modified.
	ResourceDescription `json:"resources,omitempty"`
}

// Mutation defines how resource are modified.
type Mutation struct {
	// MutateExistingOnPolicyUpdate controls if the mutateExisting rule will be applied on policy events.
	// +optional
	MutateExistingOnPolicyUpdate *bool `json:"mutateExistingOnPolicyUpdate,omitempty"`

	// Targets defines the target resources to be mutated.
	// +optional
	Targets []TargetResourceSpec `json:"targets,omitempty"`

	// PatchStrategicMerge is a strategic merge patch used to modify resources.
	// See https://kubernetes.io/docs/tasks/manage-kubernetes-objects/update-api-object-kubectl-patch/
	// and https://kubectl.docs.kubernetes.io/references/kustomize/kustomization/patchesstrategicmerge/.
	// +optional
	RawPatchStrategicMerge *apiextv1.JSON `json:"patchStrategicMerge,omitempty"`

	// PatchesJSON6902 is a list of RFC 6902 JSON Patch declarations used to modify resources.
	// See https://tools.ietf.org/html/rfc6902 and https://kubectl.docs.kubernetes.io/references/kustomize/kustomization/patchesjson6902/.
	// +optional
	PatchesJSON6902 string `json:"patchesJson6902,omitempty"`

	// ForEach applies mutation rules to a list of sub-elements by creating a context for each entry in the list and looping over it to apply the specified logic.
	// +optional
	ForEachMutation []ForEachMutation `json:"foreach,omitempty"`
}

// ForEachMutation applies mutation rules to a list of sub-elements by creating a context for each entry in the list and looping over it to apply the specified logic.
type ForEachMutation struct {
	// List specifies a JMESPath expression that results in one or more elements
	// to which the validation logic is applied.
	List string `json:"list,omitempty"`

	// Order defines the iteration order on the list.
	// Can be Ascending to iterate from first to last element or Descending to iterate in from last to first element.
	// +optional
	Order *ForeachOrder `json:"order,omitempty"`

	// Context defines variables and data sources that can be used during rule execution.
	// +optional
	Context []ContextEntry `json:"context,omitempty"`

	// AnyAllConditions are used to determine if a policy rule should be applied by evaluating a
	// set of conditions. The declaration can contain nested `any` or `all` statements.
	// See: https://kyverno.io/docs/writing-policies/preconditions/
	// +kubebuilder:validation:XPreserveUnknownFields
	// +optional
	AnyAllConditions *AnyAllConditions `json:"preconditions,omitempty"`

	// PatchStrategicMerge is a strategic merge patch used to modify resources.
	// See https://kubernetes.io/docs/tasks/manage-kubernetes-objects/update-api-object-kubectl-patch/
	// and https://kubectl.docs.kubernetes.io/references/kustomize/kustomization/patchesstrategicmerge/.
	// +optional
	// +kubebuilder:validation:Schemaless
	// +kubebuilder:pruning:PreserveUnknownFields
	RawPatchStrategicMerge *kyverno.Any `json:"patchStrategicMerge,omitempty"`

	// PatchesJSON6902 is a list of RFC 6902 JSON Patch declarations used to modify resources.
	// See https://tools.ietf.org/html/rfc6902 and https://kubectl.docs.kubernetes.io/references/kustomize/kustomization/patchesjson6902/.
	// +optional
	PatchesJSON6902 string `json:"patchesJson6902,omitempty"`

	// Foreach declares a nested foreach iterator
	// +optional
	// +kubebuilder:validation:Schemaless
	// +kubebuilder:pruning:PreserveUnknownFields
	ForEachMutation *ForEachMutationWrapper `json:"foreach,omitempty"`
}

// Validation defines checks to be performed on matching resources.
type Validation struct {
	// FailureAction defines if a validation policy rule violation should block
	// the admission review request (Enforce), or allow (Audit) the admission review request
	// and report an error in a policy report. Optional.
	// Allowed values are Audit or Enforce.
	// +optional
	// +kubebuilder:validation:Enum=Audit;Enforce
	FailureAction *ValidationFailureAction `json:"failureAction,omitempty"`

	// FailureActionOverrides is a Cluster Policy attribute that specifies FailureAction
	// namespace-wise. It overrides FailureAction for the specified namespaces.
	// +optional
	FailureActionOverrides []ValidationFailureActionOverride `json:"failureActionOverrides,omitempty"`

	// AllowExistingViolations allows prexisting violating resources to continue violating a policy.
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=true
	AllowExistingViolations *bool `json:"allowExistingViolations,omitempty"`

	// Message specifies a custom message to be displayed on failure.
	// +optional
	Message string `json:"message,omitempty"`

	// Manifest specifies conditions for manifest verification
	// +optional
	Manifests *Manifests `json:"manifests,omitempty"`

	// ForEach applies validate rules to a list of sub-elements by creating a context for each entry in the list and looping over it to apply the specified logic.
	// +optional
	ForEachValidation []ForEachValidation `json:"foreach,omitempty"`

	// Pattern specifies an overlay-style pattern used to check resources.
	// +optional
	RawPattern *apiextv1.JSON `json:"pattern,omitempty"`

	// AnyPattern specifies list of validation patterns. At least one of the patterns
	// must be satisfied for the validation rule to succeed.
	// +optional
	RawAnyPattern *apiextv1.JSON `json:"anyPattern,omitempty"`

	// Deny defines conditions used to pass or fail a validation rule.
	// +optional
	Deny *Deny `json:"deny,omitempty"`

	// PodSecurity applies exemptions for Kubernetes Pod Security admission
	// by specifying exclusions for Pod Security Standards controls.
	// +optional
	PodSecurity *PodSecurity `json:"podSecurity,omitempty"`

	// CEL allows validation checks using the Common Expression Language (https://kubernetes.io/docs/reference/using-api/cel/).
	// +optional
	CEL *CEL `json:"cel,omitempty"`

	// Assert defines a kyverno-json assertion tree.
	// +optional
	Assert AssertionTree `json:"assert"`
}

// PodSecurity applies exemptions for Kubernetes Pod Security admission
// by specifying exclusions for Pod Security Standards controls.
type PodSecurity struct {
	// Level defines the Pod Security Standard level to be applied to workloads.
	// Allowed values are privileged, baseline, and restricted.
	// +kubebuilder:validation:Enum=privileged;baseline;restricted
	Level api.Level `json:"level,omitempty"`

	// Version defines the Pod Security Standard versions that Kubernetes supports.
	// Allowed values are v1.19, v1.20, v1.21, v1.22, v1.23, v1.24, v1.25, v1.26, v1.27, v1.28, v1.29, latest. Defaults to latest.
	// +kubebuilder:validation:Enum=v1.19;v1.20;v1.21;v1.22;v1.23;v1.24;v1.25;v1.26;v1.27;v1.28;v1.29;latest
	// +optional
	Version string `json:"version,omitempty"`

	// Exclude specifies the Pod Security Standard controls to be excluded.
	Exclude []PodSecurityStandard `json:"exclude,omitempty"`
}

// PodSecurityStandard specifies the Pod Security Standard controls to be excluded.
type PodSecurityStandard struct {
	// ControlName specifies the name of the Pod Security Standard control.
	// See: https://kubernetes.io/docs/concepts/security/pod-security-standards/
	// +kubebuilder:validation:Enum=HostProcess;Host Namespaces;Privileged Containers;Capabilities;HostPath Volumes;Host Ports;AppArmor;SELinux;/proc Mount Type;Seccomp;Sysctls;Volume Types;Privilege Escalation;Running as Non-root;Running as Non-root user
	ControlName string `json:"controlName"`

	// Images selects matching containers and applies the container level PSS.
	// Each image is the image name consisting of the registry address, repository, image, and tag.
	// Empty list matches no containers, PSS checks are applied at the pod level only.
	// Wildcards ('*' and '?') are allowed. See: https://kubernetes.io/docs/concepts/containers/images.
	// +optional
	Images []string `json:"images,omitempty"`

	// RestrictedField selects the field for the given Pod Security Standard control.
	// When not set, all restricted fields for the control are selected.
	// +optional
	RestrictedField string `json:"restrictedField,omitempty"`

	// Values defines the allowed values that can be excluded.
	// +optional
	Values []string `json:"values,omitempty"`
}

// CEL allows validation checks using the Common Expression Language (https://kubernetes.io/docs/reference/using-api/cel/).
type CEL struct {
	// Generate specifies whether to generate a Kubernetes ValidatingAdmissionPolicy from the rule.
	// Optional. Defaults to "false" if not specified.
	// +optional
	// +kubebuilder:default=false
	Generate *bool `json:"generate,omitempty"`

	// Expressions is a list of CELExpression types.
	Expressions []admissionregistrationv1.Validation `json:"expressions,omitempty"`

	// ParamKind is a tuple of Group Kind and Version.
	// +optional
	ParamKind *admissionregistrationv1.ParamKind `json:"paramKind,omitempty"`

	// ParamRef references a parameter resource.
	// +optional
	ParamRef *admissionregistrationv1.ParamRef `json:"paramRef,omitempty"`

	// AuditAnnotations contains CEL expressions which are used to produce audit annotations for the audit event of the API request.
	// +optional
	AuditAnnotations []admissionregistrationv1.AuditAnnotation `json:"auditAnnotations,omitempty"`

	// Variables contain definitions of variables that can be used in composition of other expressions.
	// Each variable is defined as a named CEL expression.
	// The variables defined here will be available under `variables` in other expressions of the policy.
	// +optional
	Variables []admissionregistrationv1.Variable `json:"variables,omitempty"`
}

// Deny specifies a list of conditions used to pass or fail a validation rule.
type Deny struct {
	// Multiple conditions can be declared under an `any` or `all` statement. A direct list
	// of conditions (without `any` or `all` statements) is also supported for backwards compatibility
	// but will be deprecated in the next major release.
	// See: https://kyverno.io/docs/writing-policies/validate/#deny-rules
	// +kubebuilder:validation:Schemaless
	// +kubebuilder:pruning:PreserveUnknownFields
	RawAnyAllConditions *ConditionsWrapper `json:"conditions,omitempty"`
}

// ForEachValidation applies validate rules to a list of sub-elements by creating a context for each entry in the list and looping over it to apply the specified logic.
type ForEachValidation struct {
	// List specifies a JMESPath expression that results in one or more elements
	// to which the validation logic is applied.
	List string `json:"list,omitempty"`

	// ElementScope specifies whether to use the current list element as the scope for validation. Defaults to "true" if not specified.
	// When set to "false", "request.object" is used as the validation scope within the foreach
	// block to allow referencing other elements in the subtree.
	// +optional
	ElementScope *bool `json:"elementScope,omitempty"`

	// Context defines variables and data sources that can be used during rule execution.
	// +optional
	Context []ContextEntry `json:"context,omitempty"`

	// AnyAllConditions are used to determine if a policy rule should be applied by evaluating a
	// set of conditions. The declaration can contain nested `any` or `all` statements.
	// See: https://kyverno.io/docs/writing-policies/preconditions/
	// +kubebuilder:validation:XPreserveUnknownFields
	// +optional
	AnyAllConditions *AnyAllConditions `json:"preconditions,omitempty"`

	// Pattern specifies an overlay-style pattern used to check resources.
	// +optional
	RawPattern *apiextv1.JSON `json:"pattern,omitempty"`

	// AnyPattern specifies list of validation patterns. At least one of the patterns
	// must be satisfied for the validation rule to succeed.
	// +optional
	RawAnyPattern *apiextv1.JSON `json:"anyPattern,omitempty"`

	// Deny defines conditions used to pass or fail a validation rule.
	// +optional
	Deny *Deny `json:"deny,omitempty"`

	// Foreach declares a nested foreach iterator
	// +optional
	// +kubebuilder:validation:Schemaless
	// +kubebuilder:pruning:PreserveUnknownFields
	ForEachValidation *ForEachValidationWrapper `json:"foreach,omitempty"`
}

// Generation defines how new resources should be created and managed.
type Generation struct {
	// GenerateExisting controls whether to trigger the rule in existing resources
	// If is set to "true" the rule will be triggered and applied to existing matched resources.
	// +optional
	GenerateExisting *bool `json:"generateExisting,omitempty"`

	// Synchronize controls if generated resources should be kept in-sync with their source resource.
	// If Synchronize is set to "true" changes to generated resources will be overwritten with resource
	// data from Data or the resource specified in the Clone declaration.
	// Optional. Defaults to "false" if not specified.
	// +optional
	Synchronize bool `json:"synchronize,omitempty"`

	// OrphanDownstreamOnPolicyDelete controls whether generated resources should be deleted when the rule that generated
	// them is deleted with synchronization enabled. This option is only applicable to generate rules of the data type.
	// See https://kyverno.io/docs/writing-policies/generate/#data-examples.
	// Defaults to "false" if not specified.
	// +optional
	OrphanDownstreamOnPolicyDelete bool `json:"orphanDownstreamOnPolicyDelete,omitempty"`

	// +optional
	GeneratePattern `json:",omitempty"`

	// ForEach applies generate rules to a list of sub-elements by creating a context for each entry in the list and looping over it to apply the specified logic.
	// +optional
	ForEachGeneration []ForEachGeneration `json:"foreach,omitempty"`
}

type GeneratePattern struct {
	// ResourceSpec contains information to select the resource.
	// +kubebuilder:validation:Optional
	ResourceSpec `json:",omitempty"`

	// Data provides the resource declaration used to populate each generated resource.
	// At most one of Data or Clone must be specified. If neither are provided, the generated
	// resource will be created with default data only.
	// +optional
	RawData *apiextv1.JSON `json:"data,omitempty"`

	// Clone specifies the source resource used to populate each generated resource.
	// At most one of Data or Clone can be specified. If neither are provided, the generated
	// resource will be created with default data only.
	// +optional
	Clone CloneFrom `json:"clone,omitempty"`

	// CloneList specifies the list of source resource used to populate each generated resource.
	// +optional
	CloneList CloneList `json:"cloneList,omitempty"`
}

type ForEachGeneration struct {
	// List specifies a JMESPath expression that results in one or more elements
	// to which the validation logic is applied.
	List string `json:"list,omitempty"`

	// Context defines variables and data sources that can be used during rule execution.
	// +optional
	Context []ContextEntry `json:"context,omitempty"`

	// AnyAllConditions are used to determine if a policy rule should be applied by evaluating a
	// set of conditions. The declaration can contain nested `any` or `all` statements.
	// See: https://kyverno.io/docs/writing-policies/preconditions/
	// +kubebuilder:validation:XPreserveUnknownFields
	// +optional
	AnyAllConditions *AnyAllConditions `json:"preconditions,omitempty"`

	GeneratePattern `json:",omitempty"`
}

type CloneList struct {
	// Namespace specifies source resource namespace.
	Namespace string `json:"namespace,omitempty"`

	// Kinds is a list of resource kinds.
	Kinds []string `json:"kinds,omitempty"`

	// Selector is a label selector. Label keys and values in `matchLabels`.
	// wildcard characters are not supported.
	// +optional
	Selector *metav1.LabelSelector `json:"selector,omitempty"`
}

type GenerateType string

const (
	Data  GenerateType = "Data"
	Clone GenerateType = "Clone"
)

// CloneFrom provides the location of the source resource used to generate target resources.
// The resource kind is derived from the match criteria.
type CloneFrom struct {
	// Namespace specifies source resource namespace.
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// Name specifies name of the resource.
	Name string `json:"name,omitempty"`
}

type Manifests struct {
	// Attestors specified the required attestors (i.e. authorities)
	// +kubebuilder:validation:Optional
	Attestors []AttestorSet `json:"attestors,omitempty"`

	// AnnotationDomain is custom domain of annotation for message and signature. Default is "cosign.sigstore.dev".
	// +optional
	AnnotationDomain string `json:"annotationDomain,omitempty"`

	// Fields which will be ignored while comparing manifests.
	// +optional
	IgnoreFields IgnoreFieldList `json:"ignoreFields,omitempty"`

	// DryRun configuration
	// +optional
	DryRunOption DryRunOption `json:"dryRun,omitempty"`

	// Repository is an optional alternate OCI repository to use for resource bundle reference.
	// The repository can be overridden per Attestor or Attestation.
	Repository string `json:"repository,omitempty"`
}

// DryRunOption is a configuration for dryrun.
// If enable is set to "true", manifest verification performs "dryrun & compare"
// which provides robust matching against changes by defaults and other admission controllers.
// Dryrun requires additional permissions. See config/dryrun/dryrun_rbac.yaml
type DryRunOption struct {
	Enable    bool   `json:"enable,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

type IgnoreFieldList []ObjectFieldBinding

type ObjectFieldBinding k8smanifest.ObjectFieldBinding

// AdmissionOperation can have one of the values CREATE, UPDATE, CONNECT, DELETE, which are used to match a specific action.
// +kubebuilder:validation:Enum=CREATE;CONNECT;UPDATE;DELETE
type AdmissionOperation admissionv1.Operation

const (
	Create  AdmissionOperation = AdmissionOperation(admissionv1.Create)
	Update  AdmissionOperation = AdmissionOperation(admissionv1.Update)
	Delete  AdmissionOperation = AdmissionOperation(admissionv1.Delete)
	Connect AdmissionOperation = AdmissionOperation(admissionv1.Connect)
)
