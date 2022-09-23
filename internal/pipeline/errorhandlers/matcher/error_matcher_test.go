package matcher

import (
	"testing"

	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/stretchr/testify/assert"

	"github.com/dadrus/heimdall/internal/heimdall"
)

type TestError struct {
	ID string
}

func (e *TestError) HandlerID() string {
	return e.ID
}

func (e *TestError) Error() string {
	return "Test Error"
}

func TestErrorTypeMatcher(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc       string
		em       ErrorDescriptor
		err      error
		matching bool
	}{
		{
			uc: "match error",
			em: ErrorDescriptor{
				Errors:    []error{heimdall.ErrInternal, heimdall.ErrConfiguration},
				HandlerID: "foobar",
			},
			err:      errorchain.New(&TestError{ID: "foobar"}).CausedBy(heimdall.ErrConfiguration),
			matching: true,
		},
		{
			uc: "don't match error",
			em: ErrorDescriptor{
				Errors:    []error{heimdall.ErrInternal, heimdall.ErrConfiguration},
				HandlerID: "barfoo",
			},
			err:      errorchain.New(heimdall.ErrArgument).CausedBy(&TestError{ID: "barfoo"}),
			matching: false,
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			matcher := ErrorMatcher([]ErrorDescriptor{tc.em})

			// WHEN
			matched := matcher.Match(tc.err)

			// THEN
			assert.Equal(t, tc.matching, matched)
		})
	}
}
