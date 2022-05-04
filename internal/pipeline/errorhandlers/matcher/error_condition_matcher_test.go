package matcher

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/testsupport"
)

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
			uc: "doesn't match on error only",
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
			err:      heimdall.ErrConfiguration,
			matching: false,
		},
		{
			uc: "doesn't match on ip only",
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
					"192.168.1.2",
				})
			},
			err:      heimdall.ErrArgument,
			matching: false,
		},
		{
			uc: "doesn't match on header only",
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
			matching: false,
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
		{
			uc: "matches having all matchers defined",
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
					"192.168.1.2",
				})
			},
			err:      heimdall.ErrConfiguration,
			matching: true,
		},
		{
			uc: "matches having only error matcher defined",
			matcher: ErrorConditionMatcher{
				Error: &ErrorTypeMatcher{heimdall.ErrConfiguration},
			},
			setupCtx: func(ctx *testsupport.MockContext) {
				t.Helper()
			},
			err:      heimdall.ErrConfiguration,
			matching: true,
		},
		{
			uc: "matches having only header matcher defined",
			matcher: ErrorConditionMatcher{
				Header: &HeaderMatcher{"foobar": {"bar", "foo"}},
			},
			setupCtx: func(ctx *testsupport.MockContext) {
				t.Helper()

				ctx.On("RequestHeaders").Return(map[string]string{
					"foobar": "bar",
				})
			},
			err:      heimdall.ErrArgument,
			matching: true,
		},
		{
			uc: "matches having only cidr matcher defined",
			matcher: ErrorConditionMatcher{
				CIDR: cidrMatcher,
			},
			setupCtx: func(ctx *testsupport.MockContext) {
				t.Helper()

				ctx.On("RequestClientIPs").Return([]string{
					"192.168.1.2",
				})
			},
			err:      heimdall.ErrConfiguration,
			matching: true,
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
