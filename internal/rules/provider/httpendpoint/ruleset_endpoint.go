package httpendpoint

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/endpoint"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/provider/rulesetparser"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type ruleSetEndpoint struct {
	endpoint.Endpoint `mapstructure:",squash"`

	ExpectedPathPrefix string `mapstructure:"expected_path_prefix"`
}

func (e *ruleSetEndpoint) ID() string { return e.URL }

func (e *ruleSetEndpoint) FetchRuleSet(ctx context.Context) (*RuleSet, error) {
	req, err := e.CreateRequest(ctx, nil, nil)
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed creating request").
			CausedBy(err)
	}

	client := e.CreateClient(req.URL.Hostname())

	resp, err := client.Do(req)
	if err != nil {
		var clientErr *url.Error
		if errors.As(err, &clientErr) && clientErr.Timeout() {
			return nil, errorchain.
				NewWithMessage(heimdall.ErrCommunicationTimeout, "request to rule set endpoint timed out").
				CausedBy(err)
		}

		return nil, errorchain.
			NewWithMessage(heimdall.ErrCommunication, "request to rule set endpoint failed").
			CausedBy(err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errorchain.NewWithMessagef(heimdall.ErrCommunication,
			"unexpected response code: %v", resp.StatusCode)
	}

	md := sha256.New()

	contents, err := e.readContents(resp.Header.Get("Content-Type"), io.TeeReader(resp.Body, md))
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal, "failed to decode received rule set").
			CausedBy(err)
	}

	if err = e.verifyPathPrefix(contents); err != nil {
		return nil, err
	}

	return &RuleSet{
		Rules: contents,
		Hash:  md.Sum(nil),
	}, nil
}

func (e *ruleSetEndpoint) readContents(contentType string, reader io.Reader) ([]config.RuleConfig, error) {
	switch contentType {
	case "application/yaml":
		return rulesetparser.ParseYAML(reader)
	case "application/json":
		return rulesetparser.ParseJSON(reader)
	default:
		// check if the contents are empty. in that case nothing needs to be decoded anyway
		b := make([]byte, 1)
		if _, err := reader.Read(b); err != nil && errors.Is(err, io.EOF) {
			return []config.RuleConfig{}, nil
		}

		// otherwise
		return nil, errorchain.NewWithMessagef(heimdall.ErrInternal,
			"unsupported '%s' content type", contentType)
	}
}

func (e *ruleSetEndpoint) init() error {
	if err := e.Validate(); err != nil {
		return errorchain.NewWithMessage(heimdall.ErrConfiguration, "validation of a ruleset endpoint failed").
			CausedBy(err)
	}

	e.Method = http.MethodGet

	return nil
}

func (e *ruleSetEndpoint) verifyPathPrefix(ruleSet []config.RuleConfig) error {
	if len(e.ExpectedPathPrefix) == 0 {
		return nil
	}

	for _, ruleConfig := range ruleSet {
		if strings.HasPrefix(ruleConfig.URL, "/") &&
			// only path is specified
			!strings.HasPrefix(ruleConfig.URL, e.ExpectedPathPrefix) ||
			// patterns are specified before the path
			// There should be a better way to check it
			!strings.Contains(ruleConfig.URL, e.ExpectedPathPrefix) {
			return errorchain.NewWithMessage(heimdall.ErrConfiguration,
				"path prefix validation failed for rule ID=%s")
		}
	}

	return nil
}
