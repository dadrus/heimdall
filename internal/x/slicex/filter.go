package slicex

func Filter[T any](src []T, apply func(T) bool) []T {
	var dst []T

	for _, n := range src {
		if apply(n) {
			dst = append(dst, n)
		}
	}

	return dst
}
