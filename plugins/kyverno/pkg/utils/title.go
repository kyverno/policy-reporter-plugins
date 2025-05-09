package utils

import (
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

func Title(s string) string {
	if s == "" {
		return s
	}

	return cases.Title(language.English, cases.NoLower).String(s)
}
