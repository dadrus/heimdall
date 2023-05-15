package authenticators

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/rules/mechanisms/authenticators/extractors/mocks"
)

func TestHeaderForwardStrategyApply(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc       string
		strategy HeaderForwardStrategy
		assert   func(t *testing.T, header http.Header)
	}{
		{
			uc:       "without scheme",
			strategy: HeaderForwardStrategy{Name: "token"},
			assert: func(t *testing.T, header http.Header) {
				t.Helper()

				assert.Equal(t, "Foo", header.Get("token"))
			},
		},
		{
			uc:       "with scheme",
			strategy: HeaderForwardStrategy{Name: "token", Scheme: "Bar"},
			assert: func(t *testing.T, header http.Header) {
				t.Helper()

				values := strings.Split(header.Get("token"), " ")
				require.Len(t, values, 2)
				assert.Equal(t, "Bar", values[0])
				assert.Equal(t, "Foo", values[1])
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			ad := mocks.NewAuthDataMock(t)
			ad.EXPECT().Value().Return("Foo")

			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://test.com", nil)
			require.NoError(t, err)

			// WHEN
			tc.strategy.Apply(ad, req)

			// THEN
			tc.assert(t, req.Header)
		})
	}
}
