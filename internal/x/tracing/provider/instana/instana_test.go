package instana_test

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/goccy/go-json"
	"github.com/opentracing/opentracing-go"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/x/tracing/provider/instana"
)

func TestInstanaTracer(t *testing.T) {
	t.Parallel()

	done := make(chan struct{})

	type discoveryRequest struct {
		PID   int      `json:"pid"`
		Name  string   `json:"name"`
		Args  []string `json:"args"`
		Fd    string   `json:"fd"`
		Inode string   `json:"inode"`
	}

	// nolint: tagliatelle
	type discoveryResponse struct {
		Pid     uint32 `json:"pid"`
		HostID  string `json:"agentUuid"`
		Secrets struct {
			Matcher string   `json:"matcher"`
			List    []string `json:"list"`
		} `json:"secrets"`
		ExtraHTTPHeaders []string `json:"extraHeaders"`
	}

	type traceRequest struct {
		Timestamp uint64 `json:"ts"`
		Data      struct {
			Service string `json:"service"`
			Sdk     struct {
				Name   string `json:"name"`
				Type   string `json:"type"`
				Custom struct {
					Baggage map[string]interface{}            `json:"baggage"`
					Logs    map[uint64]map[string]interface{} `json:"logs"`
					Tags    map[string]interface{}            `json:"tags"`
				} `json:"custom"`
			} `json:"sdk"`
		} `json:"data"`
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			t.Log("Got Agent check request")

			w.Header().Set("Server", "Instana Agent")
			w.WriteHeader(http.StatusOK)

			return
		}

		if r.URL.Path == "/com.instana.plugin.golang.discovery" {
			t.Log("Got Agent discovery request")

			body, err := ioutil.ReadAll(r.Body)
			assert.NoError(t, err)

			var dReq discoveryRequest
			assert.NoError(t, json.Unmarshal(body, &dReq))

			agentResponse := discoveryResponse{
				Pid:    1,
				HostID: "1",
			}
			resp, err := json.Marshal(&agentResponse)
			assert.NoError(t, err)

			w.Header().Set("Server", "Instana Agent")

			_, err = w.Write(resp)
			require.NoError(t, err)

			return
		}

		if strings.Contains(r.URL.Path, "/com.instana.plugin.golang/traces.") {
			t.Log("Got trace request")

			body, err := ioutil.ReadAll(r.Body)
			assert.NoError(t, err)

			var req []traceRequest
			assert.NoError(t, json.Unmarshal(body, &req))

			assert.Equal(t, "heimdall", req[0].Data.Service)
			assert.Equal(t, "testOperation", req[0].Data.Sdk.Name)
			assert.Equal(t, true, req[0].Data.Sdk.Custom.Tags["testTag"])
			assert.Equal(t, "biValue", req[0].Data.Sdk.Custom.Baggage["testBi"])

			w.Header().Set("Server", "Instana Agent")
			w.WriteHeader(http.StatusOK)

			close(done)

			return
		}
	}))
	defer ts.Close()

	agentURL, err := url.Parse(ts.URL)
	require.NoError(t, err)

	require.NoError(t, os.Setenv("INSTANA_AGENT_HOST", agentURL.Hostname()))
	require.NoError(t, os.Setenv("INSTANA_AGENT_PORT", agentURL.Port()))

	tracer, _, err := instana.New("heimdall", log.Logger)
	assert.NoError(t, err)

	time.Sleep(1 * time.Second)

	opentracing.SetGlobalTracer(tracer)

	span := opentracing.GlobalTracer().StartSpan("testOperation")
	span.SetTag("testTag", true)
	span.LogKV("testKey", "testValue")
	span.SetBaggageItem("testBi", "biValue")
	span.Finish()

	select {
	case <-done:
	case <-time.After(time.Second * 3):
		t.Fatalf("Test server did not receive spans")
	}
}
