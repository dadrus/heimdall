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

package management

import (
	"net/http"

	"github.com/go-http-utils/etag"
	"github.com/go-jose/go-jose/v4"
	"github.com/goccy/go-json"
	"github.com/justinas/alice"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/handler/middleware/http/errorhandler"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/methodfilter"
	"github.com/dadrus/heimdall/internal/heimdall"
)

func newManagementHandler(signer heimdall.JWTSigner, eh errorhandler.ErrorHandler) http.Handler {
	mh := &handler{
		s:  signer,
		eh: eh,
	}

	mux := http.NewServeMux()

	mux.Handle(EndpointHealth,
		alice.New(methodfilter.New(http.MethodGet)).
			Then(http.HandlerFunc(mh.health)))
	mux.Handle(EndpointJWKS,
		alice.New(methodfilter.New(http.MethodGet)).
			Then(etag.Handler(http.HandlerFunc(mh.jwks), false)))

	return mux
}

type handler struct {
	s  heimdall.JWTSigner
	eh errorhandler.ErrorHandler
}

// jwks implements an endpoint returning JWKS objects according to
// https://datatracker.ietf.org/doc/html/rfc7517
func (h *handler) jwks(rw http.ResponseWriter, req *http.Request) {
	res, err := json.Marshal(jose.JSONWebKeySet{Keys: h.s.Keys()})
	if err != nil {
		zerolog.Ctx(req.Context()).Error().Err(err).Msg("Failed to marshal json web key set object")
		h.eh.HandleError(rw, req, err)

		return
	}

	rw.Header().Set("Content-Type", "application/json")
	_, _ = rw.Write(res)
}

func (h *handler) health(rw http.ResponseWriter, req *http.Request) {
	type status struct {
		Status string `json:"status"`
	}

	res, err := json.Marshal(status{Status: "ok"})
	if err != nil {
		zerolog.Ctx(req.Context()).Error().Err(err).Msg("Failed to marshal status object")
		h.eh.HandleError(rw, req, err)

		return
	}

	rw.Header().Set("Content-Type", "application/json")
	_, _ = rw.Write(res)
}
