package kyverno

import (
	"gopkg.in/yaml.v2"
)

func mapContent(policy map[string]any) string {
	if policy == nil {
		return ""
	}

	metadata := policy["metadata"].(map[string]any)

	delete(metadata, "managedFields")
	delete(metadata, "creationTimestamp")
	delete(metadata, "generation")
	delete(metadata, "resourceVersion")
	delete(metadata, "uid")

	if annotations, ok := metadata["annotations"]; ok {
		delete(annotations.(map[string]any), "kubectl.kubernetes.io/last-applied-configuration")
	}

	content, err := yaml.Marshal(policy)
	if err != nil {
		return ""
	}

	return string(content)
}

func toBoolString(value any) string {
	v, ok := value.(bool)
	if !ok {
		return ""
	}

	if v {
		return "enabled"
	}

	return "disabled"
}
