package utils

// Defaults returns value unless it's empty, in which case it returns
// fallback.
func Defaults(value, fallback string) string {
	if value != "" {
		return value
	}

	return fallback
}
