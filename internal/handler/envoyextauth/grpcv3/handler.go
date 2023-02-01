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

package grpcv3

import (
	"context"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type Handler struct {
	r rules.Repository
	s heimdall.JWTSigner
}

func (h *Handler) Check(ctx context.Context, req *envoy_auth.CheckRequest) (*envoy_auth.CheckResponse, error) {
	logger := zerolog.Ctx(ctx)
	logger.Debug().Msg("Decision Envoy ExtAuth endpoint called")

	reqCtx := NewRequestContext(ctx, req, h.s)

	rule, err := h.r.FindRule(reqCtx.RequestURL())
	if err != nil {
		return nil, err
	}

	if !rule.MatchesMethod(reqCtx.RequestMethod()) {
		return nil, errorchain.NewWithMessagef(heimdall.ErrMethodNotAllowed,
			"rule doesn't match %s method", reqCtx.RequestMethod())
	}

	_, err = rule.Execute(reqCtx)
	if err != nil {
		return nil, err
	}

	logger.Debug().Msg("Finalizing request")

	return reqCtx.Finalize()
}
