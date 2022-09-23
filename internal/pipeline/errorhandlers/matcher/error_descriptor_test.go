package matcher

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type testHandlerIdentifier struct {
	ID string
}

func (t *testHandlerIdentifier) HandlerID() string { return t.ID }

func TestErrorDescriptorMatches(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc            string
		errDescriptor ErrorDescriptor
		errToMatch    error
		matching      bool
	}{
		{
			uc: "with single error which does not match",
			errDescriptor: ErrorDescriptor{
				Errors: []error{heimdall.ErrInternal},
			},
			errToMatch: heimdall.ErrArgument,
			matching:   false,
		},
		{
			uc: "with multiple errors which do not match",
			errDescriptor: ErrorDescriptor{
				Errors: []error{heimdall.ErrInternal, heimdall.ErrArgument},
			},
			errToMatch: heimdall.ErrConfiguration,
			matching:   false,
		},
		{
			uc: "with single matching error",
			errDescriptor: ErrorDescriptor{
				Errors: []error{heimdall.ErrArgument},
			},
			errToMatch: heimdall.ErrArgument,
			matching:   true,
		},
		{
			uc: "with multiple errors, which one matching",
			errDescriptor: ErrorDescriptor{
				Errors: []error{heimdall.ErrInternal, heimdall.ErrArgument},
			},
			errToMatch: heimdall.ErrArgument,
			matching:   true,
		},
		{
			uc: "with matching error but not present but expected handler id",
			errDescriptor: ErrorDescriptor{
				Errors:    []error{heimdall.ErrArgument},
				HandlerID: "foo",
			},
			errToMatch: heimdall.ErrArgument,
			matching:   false,
		},
		{
			uc: "with matching error but not matching handler id",
			errDescriptor: ErrorDescriptor{
				Errors:    []error{heimdall.ErrArgument},
				HandlerID: "foo",
			},
			errToMatch: errorchain.New(heimdall.ErrArgument).WithErrorContext(&testHandlerIdentifier{ID: "bar"}),
			matching:   false,
		},
		{
			uc: "with matching error and matching handler id",
			errDescriptor: ErrorDescriptor{
				Errors:    []error{heimdall.ErrArgument},
				HandlerID: "foo",
			},
			errToMatch: errorchain.New(heimdall.ErrArgument).WithErrorContext(&testHandlerIdentifier{ID: "foo"}),
			matching:   true,
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// WHEN
			matched := tc.errDescriptor.Matches(tc.errToMatch)

			// THEN
			assert.Equal(t, tc.matching, matched)
		})
	}
}
