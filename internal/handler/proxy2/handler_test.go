package proxy2

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	mocks3 "github.com/dadrus/heimdall/internal/handler/request/mocks"
	"github.com/dadrus/heimdall/internal/rules/rule/mocks"
	"github.com/dadrus/heimdall/internal/x"
)

func TestHandlerServeHTTP(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc  string
		err bool
	}{
		{"no error", false},
		{"with error", true},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			targetURL, err := url.Parse("https://foo.bar/baz")
			require.NoError(t, err)

			testErr := errors.New("test")

			re := mocks.NewExecutorMock(t)
			rcf := mocks3.NewContextFactoryMock(t)
			rc := mocks3.NewContextMock(t)

			proxy := newHandler(rcf, re)

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			rw := httptest.NewRecorder()

			rc.EXPECT().UpstreamURLRequired().Return(true)
			rcf.EXPECT().Create(rw, req).Return(rc)
			re.EXPECT().Execute(rc, true).Return(targetURL, x.IfThenElse(tc.err, testErr, nil))

			if !tc.err {
				rc.EXPECT().Finalize(targetURL)
			} else {
				rc.EXPECT().Error(testErr)
			}

			// WHEN -> THEN expectations are met
			proxy.ServeHTTP(rw, req)
		})
	}
}
