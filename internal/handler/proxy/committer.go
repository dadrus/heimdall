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
	"context"
	"errors"
	"net/http"
	"net/http/httputil"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type proxyInvocation struct {
	request *requestContext
	err     error
}

type proxyInvocationKey struct{}

func proxyInvocationFrom(ctx context.Context) *proxyInvocation {
	invocation, ok := ctx.Value(proxyInvocationKey{}).(*proxyInvocation)
	if !ok {
		panic("proxy invocation missing")
	}

	return invocation
}

type committer struct {
	proxy *httputil.ReverseProxy
}

func newCommitter(rt http.RoundTripper) *committer {
	return &committer{
		proxy: &httputil.ReverseProxy{
			Rewrite:      rewriteRequest,
			ErrorHandler: handleProxyError,
			Transport:    rt,
			BufferPool:   newBufferPool(),
		},
	}
}

func (c *committer) Commit(rw http.ResponseWriter, rc *requestContext) (struct{}, error) {
	if !rc.hasUpstreamTarget {
		return struct{}{}, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"No upstream reference defined",
		)
	}

	zerolog.Ctx(rc.Context()).Info().
		Str("_method", rc.Request().Method).
		Str("_upstream", rc.routingURL.String()).
		Msg("Forwarding request")

	invocation := proxyInvocation{
		request: rc,
	}

	ctx := context.WithValue(
		rc.req.Context(),
		proxyInvocationKey{},
		&invocation,
	)

	c.proxy.ServeHTTP(rw, rc.req.WithContext(ctx))

	return struct{}{}, invocation.err
}

func rewriteRequest(req *httputil.ProxyRequest) {
	invocation := proxyInvocationFrom(req.In.Context())

	invocation.request.rewriteRequest(req)
}

func handleProxyError(_ http.ResponseWriter, req *http.Request, err error) {
	invocation := proxyInvocationFrom(req.Context())
	perr := pipeline.ErrCommunication

	if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
		perr = pipeline.ErrRequestBodyTooLarge
	}

	zerolog.Ctx(req.Context()).
		Error().
		Err(err).
		Msg("Proxying error")

	invocation.err = errorchain.NewWithMessage(perr, "Failed to proxy request").
		CausedBy(err)
}
