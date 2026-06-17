package oauth2

import (
	"errors"
	"net/http"

	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/x/httpx"
)

const wwwAuthenticateHeader = "Www-Authenticate"

type TokenUsageErrorDecorator struct {
	Enabled               *bool  `mapstructure:"enabled"`
	IncludeErrorDetails   *bool  `mapstructure:"include_error_description"`
	IncludeRequiredScope  *bool  `mapstructure:"include_required_scope"`
	IncludeDPoPAlgorithms *bool  `mapstructure:"include_dpop_algorithms"`
	ErrorURI              string `mapstructure:"error_uri"                 validate:"omitempty,uri"`
	Realm                 string `mapstructure:"realm"`
}

func (d TokenUsageErrorDecorator) Merge(
	other TokenUsageErrorDecorator,
) TokenUsageErrorDecorator {
	if d.Enabled == nil {
		d.Enabled = other.Enabled
	}

	if d.IncludeErrorDetails == nil {
		d.IncludeErrorDetails = other.IncludeErrorDetails
	}

	if d.IncludeRequiredScope == nil {
		d.IncludeRequiredScope = other.IncludeRequiredScope
	}

	if d.IncludeDPoPAlgorithms == nil {
		d.IncludeDPoPAlgorithms = other.IncludeDPoPAlgorithms
	}

	if len(d.ErrorURI) == 0 {
		d.ErrorURI = other.ErrorURI
	}

	if len(d.Realm) == 0 {
		d.Realm = other.Realm
	}

	return d
}

func (d TokenUsageErrorDecorator) Decorate(
	cause error,
	er *pipeline.ErrorResponse,
) {
	if d.Enabled == nil || !*d.Enabled {
		return
	}

	var challenger Challenger
	if !errors.As(cause, &challenger) {
		return
	}

	challenge, err := challenger.Challenge(d.challengePolicy())
	if err != nil {
		er.Code = http.StatusInternalServerError

		return
	}

	er.Code = challenge.StatusCode

	for name, values := range challenge.Headers {
		for _, value := range values {
			er.AddHeader(name, httpx.NewHeader(httpx.WithValue(value)))
		}
	}
}

func (d TokenUsageErrorDecorator) challengePolicy() ChallengePolicy {
	policy := ChallengePolicy{
		Realm:    d.Realm,
		ErrorURI: d.ErrorURI,
	}

	if d.IncludeErrorDetails != nil {
		policy.IncludeErrorDetails = *d.IncludeErrorDetails
	}

	if d.IncludeRequiredScope != nil {
		policy.IncludeRequiredScopes = *d.IncludeRequiredScope
	}

	if d.IncludeDPoPAlgorithms != nil {
		policy.IncludeDPoPAlgorithms = *d.IncludeDPoPAlgorithms
	}

	return policy
}
