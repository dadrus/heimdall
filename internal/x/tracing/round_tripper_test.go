package tracing

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opentracing-contrib/go-stdlib/nethttp"
	"github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/mocktracer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRoundTripperWithoutAvailableTracer(t *testing.T) {
	// GIVEN
	mtracer := mocktracer.New()
	mtracer.Reset()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := &http.Client{
		Transport: &RoundTripper{Next: &nethttp.Transport{}, TargetName: "test_client"},
	}

	// WHEN
	resp, err := client.Get(ts.URL)

	// THEN
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Len(t, mtracer.FinishedSpans(), 0)
}

func TestRoundTripperWithAvailableTracer(t *testing.T) {
	// GIVEN
	mtracer := mocktracer.New()
	mtracer.Reset()

	opentracing.SetGlobalTracer(mtracer)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := &http.Client{
		Transport: &RoundTripper{Next: &nethttp.Transport{}, TargetName: "test_client"},
	}

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/test", nil)
	require.NoError(t, err)

	// WHEN
	resp, err := client.Do(req)

	// THEN
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	spans := mtracer.FinishedSpans()
	assert.Len(t, spans, 1)
	assert.Equal(t, "test_client /test", spans[0].OperationName)
}
