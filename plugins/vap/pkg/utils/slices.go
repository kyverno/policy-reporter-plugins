package utils

// Map applies cb to every element of arg, returning the results in order.
func Map[T, R any](arg []T, cb func(T) R) []R {
	list := make([]R, 0, len(arg))
	for _, item := range arg {
		list = append(list, cb(item))
	}

	return list
}
