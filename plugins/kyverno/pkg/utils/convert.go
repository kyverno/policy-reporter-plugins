package utils

import (
	"fmt"
	"strings"
)

func ToBoolString(value any) string {
	v, ok := value.(bool)
	if !ok {
		return ""
	}

	if v {
		return "enabled"
	}

	return "disabled"
}

func ToString(value any) string {
	if v, ok := value.(string); ok {
		return strings.TrimSpace(v)
	}
	if v, ok := value.([]any); ok {
		return strings.TrimSpace(strings.Join(Map(v, func(a any) string { return fmt.Sprintf("%v", a) }), ", "))
	}

	return ""
}
