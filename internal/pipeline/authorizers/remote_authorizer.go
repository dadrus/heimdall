package authorizers

import (
	"context"
	"strings"

	"github.com/dadrus/heimdall/internal/heimdall"
)

type RemoteAuthorizer struct {
	Endpoint                 Endpoint
	Payload                  string
	ResponseHeadersToForward []string
}

func (a *RemoteAuthorizer) Authorize(ctx context.Context, sc *heimdall.SubjectContext) error {
	var payload string
	if a.Payload == "original_body" {
		// TODO: get original request body
	} else {
		// TODO: load template
	}

	_, err := a.Endpoint.SendRequest(ctx, strings.NewReader(payload))
	if err != nil {
		return err
	}

	for _, _ = range a.ResponseHeadersToForward {
		// TODO: get header hn from response and add it to the sc.Headers
	}

	return nil
}
