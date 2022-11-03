package slicex

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSubtract(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc       string
		slice1   []string
		slice2   []string
		expected []string
	}{
		{
			uc: "both empty",
		},
		{
			uc:     "subtraction from an empty slice is an empty slice",
			slice2: []string{"a", "b"},
		},
		{
			uc:       "subtracting an empty slice from non empty one is the non empty one",
			slice1:   []string{"a", "b"},
			expected: []string{"a", "b"},
		},
		{
			uc:       "subtraction of two different slides is the first slide",
			slice1:   []string{"a", "b"},
			slice2:   []string{"c", "d"},
			expected: []string{"a", "b"},
		},
		{
			uc: "subtraction of intersecting slides results in a slide with elements present in the first slide," +
				" but not in the second",
			slice1:   []string{"a", "b", "c", "d"},
			slice2:   []string{"a", "c", "e", "f"},
			expected: []string{"b", "d"},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			result := Subtract(tc.slice1, tc.slice2)

			assert.EqualValues(t, tc.expected, result)
		})
	}
}
