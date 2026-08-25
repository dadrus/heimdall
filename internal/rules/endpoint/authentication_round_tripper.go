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

package endpoint

import (
	"net/http"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type authenticationRoundTripper struct {
	next     http.RoundTripper
	strategy AuthenticationStrategy
}

func (rt *authenticationRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	zerolog.Ctx(req.Context()).Debug().Msg("Authenticating request")

	authenticated := *req

	if err := rt.strategy.Apply(&authenticated); err != nil {
		return nil, errorchain.
			NewWithMessage(pipeline.ErrInternal, "failed to authenticate request").
			CausedBy(err)
	}

	return rt.next.RoundTrip(&authenticated)
}
