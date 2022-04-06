package extractors

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/pipeline/testsupport"
)

func TestExtractCookieValue(t *testing.T) {
	t.Parallel()

	// GIVEN
	cookieName := "Test-Cookie"
	cookieValue := "foo"
	req, err := http.NewRequest(http.MethodGet, "foobar.local", nil)
	require.NoError(t, err)

	ctx := &testsupport.MockContext{}
	ctx.On("RequestCookie", cookieName).Return(cookieValue)

	strategy := CookieValueExtractStrategy{Name: cookieName}

	// WHEN
	val, err := strategy.GetAuthData(ctx)

	// THEN
	assert.NoError(t, err)
	assert.Equal(t, cookieValue, val.Value())

	val.ApplyTo(req)
	cookie, err := req.Cookie(cookieName)
	assert.NoError(t, err)
	assert.Equal(t, cookieValue, cookie.Value)

	ctx.AssertExpectations(t)
}
