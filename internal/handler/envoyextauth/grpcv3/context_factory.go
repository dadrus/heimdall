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

package grpcv3

import (
	"context"
	"sync"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
)

type requestInput struct {
	ctx context.Context // nolint: containedctx
	req *envoy_auth.CheckRequest
}

type contextFactory struct {
	pool *sync.Pool
}

func (cf *contextFactory) Create(input requestInput) *RequestContext {
	ctx := cf.pool.Get().(*RequestContext) //nolint: forcetypeassert
	ctx.Init(input.ctx, input.req)

	return ctx
}

func (cf *contextFactory) Destroy(rc *RequestContext) {
	rc.Reset()

	cf.pool.Put(rc)
}

func newContextFactory() *contextFactory {
	return &contextFactory{
		pool: &sync.Pool{New: func() any {
			return newRequestContext()
		}},
	}
}
