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
	"context"
	"net/http"

	"github.com/dadrus/heimdall/internal/handler/requestcontext"
	"github.com/dadrus/heimdall/internal/pipeline"
)

var _ pipeline.UpstreamRequest = (*requestContext)(nil)

type requestContext struct {
	*requestcontext.NetHTTPRequestContext

	upstreamViewPrepared bool
}

func (r *requestContext) Init(req *http.Request) {
	r.NetHTTPRequestContext.Init(req)
}

func (r *requestContext) Reset() {
	r.upstreamViewPrepared = false

	r.NetHTTPRequestContext.Reset()
}

func (r *requestContext) WithParent(ctx context.Context) pipeline.Context {
	r.SetParent(ctx)

	return r
}

func (r *requestContext) PrepareUpstreamView(_ pipeline.UpstreamTarget) {
	r.upstreamViewPrepared = true
}

func (r *requestContext) UpstreamRequest() pipeline.UpstreamRequest {
	if !r.upstreamViewPrepared {
		return nil
	}

	return r
}
