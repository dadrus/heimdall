package errorhandlers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/testsupport"
)

func TestErrorConditionMatcherValidation(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc      string
		matcher ErrorConditionMatcher
		valid   bool
	}{
		{
			uc:      "only no error conditions defined",
			matcher: ErrorConditionMatcher{CIDR: &CIDRMatcher{}, Header: &HeaderMatcher{}},
			valid:   true,
		},
		{
			uc:      "only no cidr conditions defined",
			matcher: ErrorConditionMatcher{Error: &ErrorTypeMatcher{}, Header: &HeaderMatcher{}},
			valid:   true,
		},
		{
			uc:      "only no header conditions defined",
			matcher: ErrorConditionMatcher{Error: &ErrorTypeMatcher{}, CIDR: &CIDRMatcher{}},
			valid:   true,
		},
		{
			uc:      "invalid configuration",
			matcher: ErrorConditionMatcher{},
			valid:   false,
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// WHEN
			err := tc.matcher.Validate()

			// THEN
			if tc.valid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestErrorConditionMatcherMatch(t *testing.T) {
	t.Parallel()

	cidrMatcher, err := NewCIDRMatcher([]string{"192.168.1.0/24"})
	require.NoError(t, err)

	for _, tc := range []struct {
		uc       string
		matcher  ErrorConditionMatcher
		setupCtx func(ctx *testsupport.MockContext)
		err      error
		matching bool
	}{
		{
			uc: "matches on error",
			matcher: ErrorConditionMatcher{
				Error:  &ErrorTypeMatcher{heimdall.ErrConfiguration},
				CIDR:   cidrMatcher,
				Header: &HeaderMatcher{"foobar": {"bar", "foo"}},
			},
			setupCtx: func(ctx *testsupport.MockContext) {
				t.Helper()
			},
			err:      heimdall.ErrConfiguration,
			matching: true,
		},
		{
			uc: "matches on ip",
			matcher: ErrorConditionMatcher{
				Error:  &ErrorTypeMatcher{heimdall.ErrConfiguration},
				CIDR:   cidrMatcher,
				Header: &HeaderMatcher{"foobar": {"bar", "foo"}},
			},
			setupCtx: func(ctx *testsupport.MockContext) {
				t.Helper()

				ctx.On("RequestClientIPs").Return([]string{
					"192.168.1.2",
				})
			},
			err:      heimdall.ErrArgument,
			matching: true,
		},
		{
			uc: "matches on header",
			matcher: ErrorConditionMatcher{
				Error:  &ErrorTypeMatcher{heimdall.ErrConfiguration},
				CIDR:   cidrMatcher,
				Header: &HeaderMatcher{"foobar": {"bar", "foo"}},
			},
			setupCtx: func(ctx *testsupport.MockContext) {
				t.Helper()

				ctx.On("RequestHeaders").Return(map[string]string{
					"foobar": "bar",
				})
				ctx.On("RequestClientIPs").Return([]string{
					"192.168.10.2",
				})
			},
			err:      heimdall.ErrArgument,
			matching: true,
		},
		{
			uc: "doesn't match at all",
			matcher: ErrorConditionMatcher{
				Error:  &ErrorTypeMatcher{heimdall.ErrConfiguration},
				CIDR:   cidrMatcher,
				Header: &HeaderMatcher{"foobar": {"bar", "foo"}},
			},
			setupCtx: func(ctx *testsupport.MockContext) {
				t.Helper()

				ctx.On("RequestHeaders").Return(map[string]string{
					"foobar": "barfoo",
				})
				ctx.On("RequestClientIPs").Return([]string{
					"192.168.10.2",
				})
			},
			err:      heimdall.ErrArgument,
			matching: false,
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			ctx := &testsupport.MockContext{}
			tc.setupCtx(ctx)

			// WHEN
			matched := tc.matcher.Match(ctx, tc.err)

			// THEN
			assert.Equal(t, tc.matching, matched)
			ctx.AssertExpectations(t)
		})
	}
}
