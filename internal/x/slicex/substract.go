package slicex

import "golang.org/x/exp/slices"

func Subtract[E comparable](a []E, b []E) []E {
	var result []E

	for _, s1 := range a {
		if !slices.Contains(b, s1) {
			result = append(result, s1)
		}
	}

	return result
}
