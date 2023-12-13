// Copyright 2023 Dimitrij Drus <dadrus@gmx.de>
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

package decision

import (
	"net/http"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/handler/requestcontext"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/rule"
)

func newContextFactory(
	signer heimdall.JWTSigner,
	responseCode int,
) requestcontext.ContextFactory {
	return requestcontext.FactoryFunc(func(rw http.ResponseWriter, req *http.Request) requestcontext.Context {
		return &requestContext{
			RequestContext: requestcontext.New(signer, req),
			responseCode:   responseCode,
			rw:             rw,
		}
	})
}

type requestContext struct {
	*requestcontext.RequestContext

	rw           http.ResponseWriter
	responseCode int
}

func (r *requestContext) Finalize(_ rule.Backend) error {
	if err := r.PipelineError(); err != nil {
		return err
	}

	zerolog.Ctx(r.AppContext()).Debug().Msg("Creating response")

	uh := r.UpstreamHeaders()
	for k := range uh {
		r.rw.Header().Set(k, uh.Get(k))
	}

	for k, v := range r.UpstreamCookies() {
		http.SetCookie(r.rw, &http.Cookie{Name: k, Value: v})
	}

	r.rw.WriteHeader(r.responseCode)

	return nil
}
