package utils

import (
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// Title converts a policy name (e.g. "require-team-label") into a
// human-readable title case string, used as a fallback when a
// ValidatingAdmissionPolicy has no title annotation.
func Title(s string) string {
	if s == "" {
		return s
	}

	return cases.Title(language.English, cases.NoLower).String(s)
}
