package utils

import (
	"fmt"
	"strings"
)

// ToString renders a decoded-JSON value (string, or []any of scalars) as a
// display string. Used for reading fields out of a ValidatingAdmissionPolicy's
// unstructured content, where every field arrives as `any`.
func ToString(value any) string {
	if v, ok := value.(string); ok {
		return strings.TrimSpace(v)
	}
	if v, ok := value.([]any); ok {
		return strings.TrimSpace(strings.Join(Map(v, func(a any) string { return fmt.Sprintf("%v", a) }), ", "))
	}

	return ""
}
