package oidc

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/endpoint"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/template"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

func FetchDiscoveryDocument(
	ctx heimdall.Context, ep *endpoint.Endpoint, templateData map[string]any,
) (
	*DiscoveryDocument, *errorchain.ErrorChain,
) {
	req, err := ep.CreateRequest(ctx.AppContext(), nil, endpoint.RenderFunc(func(value string) (string, error) {
		tpl, err := template.New(value)
		if err != nil {
			return "", errorchain.NewWithMessage(heimdall.ErrInternal, "failed to create template").
				CausedBy(err)
		}

		return tpl.Render(templateData)
	}))
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed creating openid discovery request").
			CausedBy(err)
	}

	resp, err := ep.CreateClient(req.URL.Hostname()).Do(req)
	if err != nil {
		var clientErr *url.Error
		if errors.As(err, &clientErr) && clientErr.Timeout() {
			return nil, errorchain.
				NewWithMessage(heimdall.ErrCommunicationTimeout, "request to openid discovery endpoint timed out").
				CausedBy(err)
		}

		return nil, errorchain.
			NewWithMessage(heimdall.ErrCommunication, "request to openid discovery endpoint failed").
			CausedBy(err)
	}

	defer resp.Body.Close()

	if !(resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices) {
		return nil, errorchain.
			NewWithMessagef(heimdall.ErrCommunication, "unexpected response code: %v", resp.StatusCode)
	}

	rawData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to read response").
			CausedBy(err)
	}

	// unmarshal the received discovery document
	var discovery DiscoveryDocument
	if err := json.Unmarshal(rawData, &discovery); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to unmarshal received discovery document").
			CausedBy(err)
	}

	return &discovery, nil
}
