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

package proxy

import (
	"net/http"
	"sync"

	"github.com/dadrus/heimdall/internal/handler/requestcontext"
)

type contextFactory struct {
	pool *sync.Pool
}

func newContextFactory() *contextFactory {
	return &contextFactory{
		pool: &sync.Pool{
			New: func() any {
				return &requestContext{
					NetHTTPRequestContext: requestcontext.New(),
				}
			},
		},
	}
}

func (cf *contextFactory) Create(req *http.Request) *requestContext {
	rc := cf.pool.Get().(*requestContext) //nolint:forcetypeassert
	rc.Init(req)

	return rc
}

func (cf *contextFactory) Destroy(rc *requestContext) {
	rc.Reset()
	cf.pool.Put(rc)
}
