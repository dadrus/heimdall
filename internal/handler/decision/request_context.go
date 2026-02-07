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
	"sync"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/handler/requestcontext"
	"github.com/dadrus/heimdall/internal/rules/rule"
)

type contextFactory struct {
	responseCode int
	pool         *sync.Pool
}

func (cf *contextFactory) Create(rw http.ResponseWriter, req *http.Request) requestcontext.Context {
	rc := cf.pool.Get().(*requestContext) //nolint: forcetypeassert

	rc.Init(rw, req, cf.responseCode)

	return rc
}

func (cf *contextFactory) Destroy(ctx requestcontext.Context) {
	rc := ctx.(*requestContext) //nolint: forcetypeassert

	rc.Reset()

	cf.pool.Put(rc)
}

func newContextFactory(
	responseCode int,
) requestcontext.ContextFactory {
	return &contextFactory{
		responseCode: responseCode,
		pool: &sync.Pool{New: func() any {
			return &requestContext{
				RequestContext: requestcontext.New(),
			}
		}},
	}
}

type requestContext struct {
	*requestcontext.RequestContext

	rw           http.ResponseWriter
	responseCode int
}

func (r *requestContext) Init(rw http.ResponseWriter, req *http.Request, code int) {
	r.rw = rw
	r.responseCode = code
	r.RequestContext.Init(req)
}

func (r *requestContext) Reset() {
	r.rw = nil
	r.responseCode = 0

	r.RequestContext.Reset()
}

func (r *requestContext) Finalize(_ rule.Backend) error {
	if err := r.Error(); err != nil {
		return err
	}

	zerolog.Ctx(r.Context()).Debug().Msg("Creating response")

	uh := r.UpstreamHeaders()
	for name, values := range uh {
		for _, value := range values {
			r.rw.Header().Add(name, value)
		}
	}

	for k, v := range r.UpstreamCookies() {
		http.SetCookie(r.rw, &http.Cookie{Name: k, Value: v})
	}

	r.rw.WriteHeader(r.responseCode)

	return nil
}
