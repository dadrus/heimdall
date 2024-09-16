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

	"github.com/dadrus/heimdall/internal/rules/rule"
)

type Handler struct {
	e rule.Executor
}

func (h *Handler) Check(ctx context.Context, req *envoy_auth.CheckRequest) (*envoy_auth.CheckResponse, error) {
	reqCtx := NewRequestContext(ctx, req)

	_, err := h.e.Execute(reqCtx)
	if err != nil {
		return nil, err
	}

	return reqCtx.Finalize()
}
