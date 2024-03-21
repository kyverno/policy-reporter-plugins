package utils

import "strings"

func SplitPolicyName(n string) (string, string) {
	parts := strings.Split(n, "/")
	if len(parts) > 1 {
		return parts[0], parts[1]
	}

	return parts[0], ""
}
