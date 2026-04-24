// Copyright 2026 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"errors"
	"net/http"
	"strings"

	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/httpx"
)

const wwwAuthenticateHeader = "WWW-Authenticate"

type BearerTokenUsageErrorDecorator struct {
	Enabled              *bool  `mapstructure:"enabled"`
	IncludeErrorDetails  *bool  `mapstructure:"include_error_description"`
	IncludeRequiredScope *bool  `mapstructure:"include_required_scope"`
	ErrorURI             string `mapstructure:"error_uri"                 validate:"omitempty,uri"`
	Realm                string `mapstructure:"realm"`
}

func (d BearerTokenUsageErrorDecorator) Merge(other BearerTokenUsageErrorDecorator) BearerTokenUsageErrorDecorator {
	if d.Enabled == nil {
		d.Enabled = other.Enabled
	}

	if d.IncludeErrorDetails == nil {
		d.IncludeErrorDetails = other.IncludeErrorDetails
	}

	if d.IncludeRequiredScope == nil {
		d.IncludeRequiredScope = other.IncludeRequiredScope
	}

	if len(d.ErrorURI) == 0 {
		d.ErrorURI = other.ErrorURI
	}

	if len(d.Realm) == 0 {
		d.Realm = other.Realm
	}

	return d
}

func (d BearerTokenUsageErrorDecorator) Decorate(err error, requiredScopes []string, er *pipeline.ErrorResponse) {
	if d.Enabled == nil || !*d.Enabled {
		return
	}

	opts := make([]httpx.Option, 0, 6)
	opts = append(opts,
		httpx.WithPrefix("Bearer"),
		httpx.WithKeyValue("realm", d.Realm),
		httpx.WithKeyValue("error_uri", d.ErrorURI),
	)

	switch {
	case errors.Is(err, pipeline.ErrArgument):
		er.Code = http.StatusBadRequest

		opts = append(opts, httpx.WithKeyValue("error", "invalid_request"))
	case errors.Is(err, ErrScopeMatch):
		er.Code = http.StatusForbidden

		opts = append(opts, httpx.WithKeyValue("error", "insufficient_scope"))

		if d.IncludeRequiredScope != nil && *d.IncludeRequiredScope {
			opts = append(opts, httpx.WithKeyValue("scope",
				strings.Join(requiredScopes, " ")))
		}
	default:
		er.Code = http.StatusUnauthorized

		opts = append(opts, httpx.WithKeyValue("error", "invalid_token"))
	}

	if d.IncludeErrorDetails != nil && *d.IncludeErrorDetails {
		cause := errors.Unwrap(err)
		opts = append(opts, httpx.WithKeyValue("error_description",
			x.IfThenElseExec(cause == nil,
				func() string { return err.Error() },
				func() string { return cause.Error() },
			)))
	}

	er.AddHeader(wwwAuthenticateHeader, httpx.NewHeader(opts...))
}
