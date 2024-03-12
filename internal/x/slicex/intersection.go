package slicex

import "slices"

func Intersects[S ~[]E, E comparable](first S, second S) bool {
	var intersection bool

	for _, f := range first {
		if slices.Contains(second, f) {
			intersection = true
			break
		}
	}

	return intersection
}
