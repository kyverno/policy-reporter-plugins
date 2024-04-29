package utils

func Defaults(value, fallback string) string {
	if value != "" {
		return value
	}

	return fallback
}
