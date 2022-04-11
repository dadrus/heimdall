package errorhandlers

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dadrus/heimdall/internal/heimdall"
)

func TestErrorTypeMatcher(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc       string
		errors   []error
		err      error
		matching bool
	}{
		{
			uc:       "match error",
			errors:   []error{heimdall.ErrInternal, heimdall.ErrConfiguration},
			err:      heimdall.ErrConfiguration,
			matching: true,
		},
		{
			uc:       "don't match error",
			errors:   []error{heimdall.ErrInternal, heimdall.ErrConfiguration},
			err:      heimdall.ErrArgument,
			matching: false,
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			matcher := ErrorTypeMatcher(tc.errors)

			// WHEN
			matched := matcher.Match(tc.err)

			// THEN
			assert.Equal(t, tc.matching, matched)
		})
	}
}
