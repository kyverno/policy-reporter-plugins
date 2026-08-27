package policy

import (
	"sigs.k8s.io/yaml"
)

// mapContent renders a ValidatingAdmissionPolicy's unstructured content as
// YAML source, after stripping server-managed metadata fields that would
// otherwise clutter the source shown in the Policy Reporter plugin API.
func mapContent(policy map[string]any) string {
	if policy == nil {
		return ""
	}

	metadata, ok := policy["metadata"].(map[string]any)
	if ok {
		delete(metadata, "managedFields")
		delete(metadata, "creationTimestamp")
		delete(metadata, "generation")
		delete(metadata, "resourceVersion")
		delete(metadata, "uid")

		if annotations, ok := metadata["annotations"].(map[string]any); ok {
			delete(annotations, "kubectl.kubernetes.io/last-applied-configuration")
		}
	}

	delete(policy, "status")

	content, err := yaml.Marshal(policy)
	if err != nil {
		return ""
	}

	return string(content)
}
