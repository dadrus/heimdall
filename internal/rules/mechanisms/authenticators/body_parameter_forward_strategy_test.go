package authenticators

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/rules/mechanisms/authenticators/extractors/mocks"
)

func TestBodyParameterForwardStrategyApply(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		contentType string
		strategy    BodyParameterForwardStrategy
		assert      func(t *testing.T, encoded []byte)
	}{
		{
			contentType: "application/x-www-form-urlencoded",
			strategy:    BodyParameterForwardStrategy{Name: "token"},
			assert: func(t *testing.T, encoded []byte) {
				t.Helper()

				query, err := url.ParseQuery(string(encoded))
				require.NoError(t, err)

				assert.Equal(t, "Foo", query.Get("token"))
			},
		},
		{
			contentType: "application/json",
			strategy:    BodyParameterForwardStrategy{Name: "token"},
			assert: func(t *testing.T, encoded []byte) {
				t.Helper()

				var data map[string]string

				err := json.Unmarshal(encoded, &data)
				require.NoError(t, err)

				assert.Equal(t, "Foo", data["token"])
			},
		},
	} {
		t.Run(tc.contentType, func(t *testing.T) {
			// GIVEN
			ad := mocks.NewAuthDataMock(t)
			ad.EXPECT().Value().Return("Foo")

			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://test.com", nil)
			require.NoError(t, err)

			req.Header.Set("Content-Type", tc.contentType)

			// WHEN
			tc.strategy.Apply(ad, req)

			// THEN
			data, err := io.ReadAll(req.Body)
			require.NoError(t, err)

			tc.assert(t, data)
		})
	}
}
