package httpendpoint

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"net/url"

	"github.com/dadrus/heimdall/internal/endpoint"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/provider/pathprefix"
	"github.com/dadrus/heimdall/internal/rules/provider/rulesetparser"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type ruleSetEndpoint struct {
	endpoint.Endpoint `mapstructure:",squash"`

	RulesPathPrefix pathprefix.PathPrefix `mapstructure:"rule_path_match_prefix"`
}

func (e *ruleSetEndpoint) ID() string { return e.URL }

func (e *ruleSetEndpoint) FetchRuleSet(ctx context.Context) (RuleSet, error) {
	req, err := e.CreateRequest(ctx, nil, nil)
	if err != nil {
		return RuleSet{}, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed creating request").
			CausedBy(err)
	}

	client := e.CreateClient(req.URL.Hostname())

	resp, err := client.Do(req)
	if err != nil {
		var clientErr *url.Error
		if errors.As(err, &clientErr) && clientErr.Timeout() {
			return RuleSet{}, errorchain.
				NewWithMessage(heimdall.ErrCommunicationTimeout, "request to rule set endpoint timed out").
				CausedBy(err)
		}

		return RuleSet{}, errorchain.
			NewWithMessage(heimdall.ErrCommunication, "request to rule set endpoint failed").
			CausedBy(err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return RuleSet{}, errorchain.NewWithMessagef(heimdall.ErrCommunication,
			"unexpected response code: %v", resp.StatusCode)
	}

	md := sha256.New()

	contents, err := rulesetparser.ParseRules(resp.Header.Get("Content-Type"), io.TeeReader(resp.Body, md))
	if err != nil {
		return RuleSet{}, errorchain.NewWithMessage(heimdall.ErrInternal, "failed to decode received rule set").
			CausedBy(err)
	}

	if err = e.RulesPathPrefix.Verify(contents); err != nil {
		return RuleSet{}, err
	}

	return RuleSet{
		Rules: contents,
		Hash:  md.Sum(nil),
	}, nil
}

func (e *ruleSetEndpoint) init() error {
	if err := e.Validate(); err != nil {
		return errorchain.NewWithMessage(heimdall.ErrConfiguration, "validation of a ruleset endpoint failed").
			CausedBy(err)
	}

	e.Method = http.MethodGet

	return nil
}
