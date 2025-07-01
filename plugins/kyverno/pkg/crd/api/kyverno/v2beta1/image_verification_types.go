package v2beta1

import (
	kyvernov1 "github.com/kyverno/policy-reporter/kyverno-plugin/pkg/crd/api/kyverno/v1"
)

// ImageVerification validates that images that match the specified pattern
// are signed with the supplied public key. Once the image is verified it is
// mutated to include the SHA digest retrieved during the registration.
type ImageVerification struct {
	// Allowed values are Audit or Enforce.
	// +optional
	// +kubebuilder:validation:Enum=Audit;Enforce
	FailureAction *kyvernov1.ValidationFailureAction `json:"failureAction,omitempty"`

	// Type specifies the method of signature validation. The allowed options
	// are Cosign and Notary. By default Cosign is used if a type is not specified.
	// +kubebuilder:validation:Optional
	Type kyvernov1.ImageVerificationType `json:"type,omitempty"`

	// ImageReferences is a list of matching image reference patterns. At least one pattern in the
	// list must match the image for the rule to apply. Each image reference consists of a registry
	// address (defaults to docker.io), repository, image, and tag (defaults to latest).
	// Wildcards ('*' and '?') are allowed. See: https://kubernetes.io/docs/concepts/containers/images.
	// +kubebuilder:validation:Optional
	ImageReferences []string `json:"imageReferences,omitempty"`

	// SkipImageReferences is a list of matching image reference patterns that should be skipped.
	// At least one pattern in the list must match the image for the rule to be skipped. Each image reference
	// consists of a registry address (defaults to docker.io), repository, image, and tag (defaults to latest).
	// Wildcards ('*' and '?') are allowed. See: https://kubernetes.io/docs/concepts/containers/images.
	// +kubebuilder:validation:Optional
	SkipImageReferences []string `json:"skipImageReferences,omitempty"`

	// Attestors specified the required attestors (i.e. authorities)
	// +kubebuilder:validation:Optional
	Attestors []kyvernov1.AttestorSet `json:"attestors,omitempty"`

	// Attestations are optional checks for signed in-toto Statements used to verify the image.
	// See https://github.com/in-toto/attestation. Kyverno fetches signed attestations from the
	// OCI registry and decodes them into a list of Statement declarations.
	Attestations []kyvernov1.Attestation `json:"attestations,omitempty"`

	// Repository is an optional alternate OCI repository to use for image signatures and attestations that match this rule.
	// If specified Repository will override the default OCI image repository configured for the installation.
	// The repository can also be overridden per Attestor or Attestation.
	Repository string `json:"repository,omitempty"`

	// MutateDigest enables replacement of image tags with digests.
	// Defaults to true.
	// +kubebuilder:default=true
	// +kubebuilder:validation:Optional
	MutateDigest bool `json:"mutateDigest"`

	// VerifyDigest validates that images have a digest.
	// +kubebuilder:default=true
	// +kubebuilder:validation:Optional
	VerifyDigest bool `json:"verifyDigest"`

	// Validation checks conditions across multiple image
	// verification attestations or context entries
	Validation kyvernov1.ValidateImageVerification `json:"validate,omitempty"`

	// Required validates that images are verified i.e. have matched passed a signature or attestation check.
	// +kubebuilder:default=true
	// +kubebuilder:validation:Optional
	Required bool `json:"required"`

	// ImageRegistryCredentials provides credentials that will be used for authentication with registry
	// +kubebuilder:validation:Optional
	ImageRegistryCredentials *kyvernov1.ImageRegistryCredentials `json:"imageRegistryCredentials,omitempty"`

	// UseCache enables caching of image verify responses for this rule
	// +kubebuilder:default=true
	// +kubebuilder:validation:Optional
	UseCache bool `json:"useCache"`
}
