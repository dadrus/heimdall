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
	"io"
	"net/http"
	"net/http/httputil"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type closeWriteReadWriteCloser struct {
	io.ReadWriteCloser
	closeWriter
}

func preserveCloseWrite(source, wrapped io.ReadWriteCloser) io.ReadWriteCloser {
	writer, ok := source.(closeWriter)
	if !ok {
		return wrapped
	}

	return &closeWriteReadWriteCloser{
		ReadWriteCloser: wrapped,
		closeWriter:     writer,
	}
}

type committer struct {
	proxy   *httputil.ReverseProxy
	tunnels tunnelTracker
}

func newCommitter(rt http.RoundTripper, tunnels tunnelTracker) *committer {
	c := &committer{
		tunnels: tunnels,
	}
	c.proxy = &httputil.ReverseProxy{
		Rewrite:        rewriteRequest,
		ErrorHandler:   handleProxyError,
		ModifyResponse: c.trackUpgradeResponse,
		Transport:      rt,
		BufferPool:     newBufferPool(),
	}

	return c
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

	writer := rw
	if rc.upgrade != upgradeKindNone {
		var teardownStrategy connectionTeardownStrategy = noopConnectionTeardownStrategy{}
		if rc.upgrade == upgradeKindWebSocket {
			teardownStrategy = webSocketServerGoingAwayTeardownStrategy
		}

		writer = &upgradeResponseWriter{
			ResponseWriter:   rw,
			tunnels:          c.tunnels,
			teardownStrategy: teardownStrategy,
		}
	}

	c.proxy.ServeHTTP(writer, rc.req.WithContext(ctx))

	return struct{}{}, invocation.err
}

func (c *committer) trackUpgradeResponse(res *http.Response) error {
	if res.StatusCode != http.StatusSwitchingProtocols {
		return nil
	}

	conn, ok := res.Body.(io.ReadWriteCloser)
	if !ok {
		return nil
	}

	var teardownStrategy connectionTeardownStrategy = noopConnectionTeardownStrategy{}
	if isWebSocketUpgradeResponse(res) {
		teardownStrategy = webSocketClientGoingAwayTeardownStrategy
	}

	endpoint, err := c.tunnels.track(conn, teardownStrategy)
	if err != nil {
		return err
	}

	res.Body = preserveCloseWrite(conn, endpoint)

	return nil
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

	invocation.err = errorchain.New(perr).CausedBy(err)
}
