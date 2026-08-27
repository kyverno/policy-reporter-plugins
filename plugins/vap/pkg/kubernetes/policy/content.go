package policy

import (
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

// lastAppliedConfigAnnotation is stripped from the rendered source, same as
// every other server-managed field below: it's kubectl bookkeeping, not
// part of the policy an operator authored.
const lastAppliedConfigAnnotation = "kubectl.kubernetes.io/last-applied-configuration"

// mapContent renders a ValidatingAdmissionPolicy as YAML source, after
// stripping server-managed fields that would otherwise clutter the source
// shown in the Policy Reporter plugin API. The lister-backed policy this
// operates on (see Client) has no TypeMeta - client-go doesn't populate it
// on objects read from an informer cache - so it's set explicitly here to
// produce a self-describing document.
func mapContent(p *admissionregistrationv1.ValidatingAdmissionPolicy) string {
	if p == nil {
		return ""
	}

	clean := p.DeepCopy()
	clean.TypeMeta = metav1.TypeMeta{
		APIVersion: admissionregistrationv1.SchemeGroupVersion.String(),
		Kind:       "ValidatingAdmissionPolicy",
	}
	clean.ManagedFields = nil
	clean.CreationTimestamp = metav1.Time{}
	clean.Generation = 0
	clean.ResourceVersion = ""
	clean.UID = ""
	clean.Status = admissionregistrationv1.ValidatingAdmissionPolicyStatus{}
	delete(clean.Annotations, lastAppliedConfigAnnotation)

	content, err := yaml.Marshal(clean)
	if err != nil {
		return ""
	}

	return string(content)
}
