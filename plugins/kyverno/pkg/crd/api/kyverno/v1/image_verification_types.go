package v1

import (
	"github.com/kyverno/policy-reporter/kyverno-plugin/pkg/crd/api/policies.kyverno.io/v1alpha1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

// ImageVerificationType selects the type of verification algorithm
// +kubebuilder:validation:Enum=Cosign;SigstoreBundle;Notary
// +kubebuilder:default=Cosign
type ImageVerificationType string

// ImageRegistryCredentialsProvidersType provides the list of credential providers required.
type ImageRegistryCredentialsProvidersType v1alpha1.CredentialsProvidersType

const (
	Cosign         ImageVerificationType = "Cosign"
	SigstoreBundle ImageVerificationType = "SigstoreBundle"
	Notary         ImageVerificationType = "Notary"

	DEFAULT ImageRegistryCredentialsProvidersType = "default"
	AWS     ImageRegistryCredentialsProvidersType = "amazon"
	ACR     ImageRegistryCredentialsProvidersType = "azure"
	GCP     ImageRegistryCredentialsProvidersType = "google"
	GHCR    ImageRegistryCredentialsProvidersType = "github"
)

var signatureAlgorithmMap = map[string]bool{
	"":       true,
	"sha224": true,
	"sha256": true,
	"sha384": true,
	"sha512": true,
}

// ImageVerification validates that images that match the specified pattern
// are signed with the supplied public key. Once the image is verified it is
// mutated to include the SHA digest retrieved during the registration.
type ImageVerification struct {
	// Allowed values are Audit or Enforce.
	// +optional
	// +kubebuilder:validation:Enum=Audit;Enforce
	FailureAction *ValidationFailureAction `json:"failureAction,omitempty"`

	// Type specifies the method of signature validation. The allowed options
	// are Cosign, Sigstore Bundle and Notary. By default Cosign is used if a type is not specified.
	// +kubebuilder:validation:Optional
	Type ImageVerificationType `json:"type,omitempty"`

	// Deprecated. Use ImageReferences instead.
	// +kubebuilder:validation:Optional
	Image string `json:"image,omitempty"`

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

	// Deprecated. Use StaticKeyAttestor instead.
	Key string `json:"key,omitempty"`

	// Deprecated. Use KeylessAttestor instead.
	Roots string `json:"roots,omitempty"`

	// Deprecated. Use KeylessAttestor instead.
	Subject string `json:"subject,omitempty"`

	// Deprecated. Use KeylessAttestor instead.
	Issuer string `json:"issuer,omitempty"`

	// Deprecated.
	AdditionalExtensions map[string]string `json:"additionalExtensions,omitempty"`

	// Attestors specified the required attestors (i.e. authorities)
	// +kubebuilder:validation:Optional
	Attestors []AttestorSet `json:"attestors,omitempty"`

	// Attestations are optional checks for signed in-toto Statements used to verify the image.
	// See https://github.com/in-toto/attestation. Kyverno fetches signed attestations from the
	// OCI registry and decodes them into a list of Statement declarations.
	Attestations []Attestation `json:"attestations,omitempty"`

	// Deprecated. Use annotations per Attestor instead.
	Annotations map[string]string `json:"annotations,omitempty"`

	// Repository is an optional alternate OCI repository to use for image signatures and attestations that match this rule.
	// If specified Repository will override the default OCI image repository configured for the installation.
	// The repository can also be overridden per Attestor or Attestation.
	Repository string `json:"repository,omitempty"`

	// CosignOCI11 enables the experimental OCI 1.1 behaviour in cosign image verification.
	// Defaults to false.
	// +optional
	CosignOCI11 bool `json:"cosignOCI11,omitempty"`

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
	Validation ValidateImageVerification `json:"validate,omitempty"`

	// Required validates that images are verified i.e. have matched passed a signature or attestation check.
	// +kubebuilder:default=true
	// +kubebuilder:validation:Optional
	Required bool `json:"required"`

	// ImageRegistryCredentials provides credentials that will be used for authentication with registry.
	// +kubebuilder:validation:Optional
	ImageRegistryCredentials *ImageRegistryCredentials `json:"imageRegistryCredentials,omitempty"`

	// UseCache enables caching of image verify responses for this rule.
	// +kubebuilder:default=true
	// +kubebuilder:validation:Optional
	UseCache bool `json:"useCache"`
}

type AttestorSet struct {
	// Count specifies the required number of entries that must match. If the count is null, all entries must match
	// (a logical AND). If the count is 1, at least one entry must match (a logical OR). If the count contains a
	// value N, then N must be less than or equal to the size of entries, and at least N entries must match.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum:=1
	Count *int `json:"count,omitempty"`

	// Entries contains the available attestors. An attestor can be a static key,
	// attributes for keyless verification, or a nested attestor declaration.
	// +kubebuilder:validation:Optional
	Entries []Attestor `json:"entries,omitempty"`
}

type Attestor struct {
	// Keys specifies one or more public keys.
	// +kubebuilder:validation:Optional
	Keys *StaticKeyAttestor `json:"keys,omitempty"`

	// Certificates specifies one or more certificates.
	// +kubebuilder:validation:Optional
	Certificates *CertificateAttestor `json:"certificates,omitempty"`

	// Keyless is a set of attribute used to verify a Sigstore keyless attestor.
	// See https://github.com/sigstore/cosign/blob/main/KEYLESS.md.
	// +kubebuilder:validation:Optional
	Keyless *KeylessAttestor `json:"keyless,omitempty"`

	// Attestor is a nested set of Attestor used to specify a more complex set of match authorities.
	// +kubebuilder:validation:Optional
	Attestor *apiextv1.JSON `json:"attestor,omitempty"`

	// Annotations are used for image verification.
	// Every specified key-value pair must exist and match in the verified payload.
	// The payload may contain other key-value pairs.
	Annotations map[string]string `json:"annotations,omitempty"`

	// Repository is an optional alternate OCI repository to use for signatures and attestations that match this rule.
	// If specified Repository will override other OCI image repository locations for this Attestor.
	Repository string `json:"repository,omitempty"`

	// Specify signature algorithm for public keys. Supported values are sha224, sha256, sha384 and sha512.
	// +kubebuilder:default=sha256
	SignatureAlgorithm string `json:"signatureAlgorithm,omitempty"`
}

type StaticKeyAttestor struct {
	// Keys is a set of X.509 public keys used to verify image signatures. The keys can be directly
	// specified or can be a variable reference to a key specified in a ConfigMap (see
	// https://kyverno.io/docs/writing-policies/variables/), or reference a standard Kubernetes Secret
	// elsewhere in the cluster by specifying it in the format "k8s://<namespace>/<secret_name>".
	// The named Secret must specify a key `cosign.pub` containing the public key used for
	// verification, (see https://github.com/sigstore/cosign/blob/main/KMS.md#kubernetes-secret).
	// When multiple keys are specified each key is processed as a separate staticKey entry
	// (.attestors[*].entries.keys) within the set of attestors and the count is applied across the keys.
	PublicKeys string `json:"publicKeys,omitempty"`

	// Deprecated. Use attestor.signatureAlgorithm instead.
	// +kubebuilder:default=sha256
	SignatureAlgorithm string `json:"signatureAlgorithm,omitempty"`

	// KMS provides the URI to the public key stored in a Key Management System. See:
	// https://github.com/sigstore/cosign/blob/main/KMS.md
	KMS string `json:"kms,omitempty"`

	// Reference to a Secret resource that contains a public key
	Secret *SecretReference `json:"secret,omitempty"`

	// Rekor provides configuration for the Rekor transparency log service. If an empty object
	// is provided the public instance of Rekor (https://rekor.sigstore.dev) is used.
	// +kubebuilder:validation:Optional
	Rekor *Rekor `json:"rekor,omitempty"`

	// CTLog (certificate timestamp log) provides a configuration for validation of Signed Certificate
	// Timestamps (SCTs). If the value is unset, the default behavior by Cosign is used.
	// +kubebuilder:validation:Optional
	CTLog *CTLog `json:"ctlog,omitempty"`
}

type SecretReference struct {
	// Name of the secret. The provided secret must contain a key named cosign.pub.
	Name string `json:"name"`

	// Namespace name where the Secret exists.
	Namespace string `json:"namespace"`
}

type CertificateAttestor struct {
	// Cert is an optional PEM-encoded public certificate.
	// +kubebuilder:validation:Optional
	Certificate string `json:"cert,omitempty"`

	// CertChain is an optional PEM encoded set of certificates used to verify.
	// +kubebuilder:validation:Optional
	CertificateChain string `json:"certChain,omitempty"`

	// Rekor provides configuration for the Rekor transparency log service. If an empty object
	// is provided the public instance of Rekor (https://rekor.sigstore.dev) is used.
	// +kubebuilder:validation:Optional
	Rekor *Rekor `json:"rekor,omitempty"`

	// CTLog (certificate timestamp log) provides a configuration for validation of Signed Certificate
	// Timestamps (SCTs). If the value is unset, the default behavior by Cosign is used.
	// +kubebuilder:validation:Optional
	CTLog *CTLog `json:"ctlog,omitempty"`
}

type KeylessAttestor struct {
	// Rekor provides configuration for the Rekor transparency log service. If an empty object
	// is provided the public instance of Rekor (https://rekor.sigstore.dev) is used.
	// +kubebuilder:validation:Optional
	Rekor *Rekor `json:"rekor,omitempty"`

	// CTLog (certificate timestamp log) provides a configuration for validation of Signed Certificate
	// Timestamps (SCTs). If the value is unset, the default behavior by Cosign is used.
	// +kubebuilder:validation:Optional
	CTLog *CTLog `json:"ctlog,omitempty"`

	// Issuer is the certificate issuer used for keyless signing.
	// +kubebuilder:validation:Optional
	Issuer string `json:"issuer,omitempty"`

	// IssuerRegExp is the regular expression to match certificate issuer used for keyless signing.
	// +kubebuilder:validation:Optional
	IssuerRegExp string `json:"issuerRegExp,omitempty"`

	// Subject is the verified identity used for keyless signing, for example the email address.
	// +kubebuilder:validation:Optional
	Subject string `json:"subject,omitempty"`

	// SubjectRegExp is the regular expression to match identity used for keyless signing, for example the email address.
	// +kubebuilder:validation:Optional
	SubjectRegExp string `json:"subjectRegExp,omitempty"`

	// Roots is an optional set of PEM encoded trusted root certificates.
	// If not provided, the system roots are used.
	// +kubebuilder:validation:Optional
	Roots string `json:"roots,omitempty"`

	// AdditionalExtensions are certificate-extensions used for keyless signing.
	// +kubebuilder:validation:Optional
	AdditionalExtensions map[string]string `json:"additionalExtensions,omitempty"`
}

type Rekor struct {
	// URL is the address of the transparency log. Defaults to the public Rekor log instance https://rekor.sigstore.dev.
	// +kubebuilder:validation:Optional
	// +kubebuilder:Default:=https://rekor.sigstore.dev
	URL string `json:"url"`

	// RekorPubKey is an optional PEM-encoded public key to use for a custom Rekor.
	// If set, this will be used to validate transparency log signatures from a custom Rekor.
	// +kubebuilder:validation:Optional
	RekorPubKey string `json:"pubkey,omitempty"`

	// IgnoreTlog skips transparency log verification.
	// +kubebuilder:validation:Optional
	IgnoreTlog bool `json:"ignoreTlog,omitempty"`
}

type CTLog struct {
	// IgnoreSCT defines whether to use the Signed Certificate Timestamp (SCT) log to check for a certificate
	// timestamp. Default is false. Set to true if this was opted out during signing.
	// +kubebuilder:validation:Optional
	IgnoreSCT bool `json:"ignoreSCT,omitempty"`

	// PubKey, if set, is used to validate SCTs against a custom source.
	// +kubebuilder:validation:Optional
	CTLogPubKey string `json:"pubkey,omitempty"`

	// TSACertChain, if set, is the PEM-encoded certificate chain file for the RFC3161 timestamp authority. Must
	// contain the root CA certificate. Optionally may contain intermediate CA certificates, and
	// may contain the leaf TSA certificate if not present in the timestamurce.
	// +kubebuilder:validation:Optional
	TSACertChain string `json:"tsaCertChain,omitempty"`
}

// Attestation are checks for signed in-toto Statements that are used to verify the image.
// See https://github.com/in-toto/attestation. Kyverno fetches signed attestations from the
// OCI registry and decodes them into a list of Statements.
type Attestation struct {
	// Name is the variable name.
	Name string `json:"name,omitempty"`

	// Deprecated in favour of 'Type', to be removed soon
	// +kubebuilder:validation:Optional
	PredicateType string `json:"predicateType"`

	// Type defines the type of attestation contained within the Statement.
	// +kubebuilder:validation:Optional
	Type string `json:"type"`

	// Attestors specify the required attestors (i.e. authorities).
	// +kubebuilder:validation:Optional
	Attestors []AttestorSet `json:"attestors"`

	// Conditions are used to verify attributes within a Predicate. If no Conditions are specified
	// the attestation check is satisfied as long there are predicates that match the predicate type.
	// +kubebuilder:validation:Optional
	Conditions []AnyAllConditions `json:"conditions,omitempty"`
}

type ImageRegistryCredentials struct {
	// AllowInsecureRegistry allows insecure access to a registry.
	// +kubebuilder:validation:Optional
	AllowInsecureRegistry bool `json:"allowInsecureRegistry,omitempty"`

	// Providers specifies a list of OCI Registry names, whose authentication providers are provided.
	// It can be of one of these values: default,google,azure,amazon,github.
	// +kubebuilder:validation:Optional
	Providers []ImageRegistryCredentialsProvidersType `json:"providers,omitempty"`

	// Secrets specifies a list of secrets that are provided for credentials.
	// Secrets must live in the Kyverno namespace.
	// +kubebuilder:validation:Optional
	Secrets []string `json:"secrets,omitempty"`
}

// ValidateImageVerification checks conditions across multiple image
// verification attestations or context entries
type ValidateImageVerification struct {
	// Message specifies a custom message to be displayed on failure.
	// +optional
	Message string `json:"message,omitempty"`

	// Deny defines conditions used to pass or fail a validation rule.
	// +optional
	Deny *Deny `json:"deny,omitempty"`
}
