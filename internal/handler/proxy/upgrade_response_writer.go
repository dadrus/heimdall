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
	"bufio"
	"io"
	"net"
	"net/http"
)

type upgradeResponseWriter struct {
	http.ResponseWriter

	tunnels          tunnelTracker
	teardownStrategy connectionTeardownStrategy
	hijacked         bool
}

func (w *upgradeResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *upgradeResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err != nil {
		return conn, rw, err
	}

	w.hijacked = true

	endpoint, err := w.tunnels.track(conn, w.teardownStrategy)
	if err != nil {
		_ = conn.Close()

		return nil, nil, err
	}

	return newHijackedConn(conn, endpoint), rw, nil
}

type hijackedConn struct {
	net.Conn

	endpoint *tunnelEndpoint
}

func (c *hijackedConn) Close() error {
	return c.endpoint.Close()
}

func (c *hijackedConn) ReadFrom(src io.Reader) (int64, error) {
	if readerFrom, ok := c.Conn.(io.ReaderFrom); ok {
		return readerFrom.ReadFrom(src)
	}

	return io.Copy(c.Conn, src)
}

type closeWriteConn struct {
	net.Conn
	io.ReaderFrom
	closeWriter
}

func newHijackedConn(conn net.Conn, endpoint *tunnelEndpoint) net.Conn {
	hijacked := &hijackedConn{
		Conn:     conn,
		endpoint: endpoint,
	}

	writer, ok := conn.(closeWriter)
	if !ok {
		return hijacked
	}

	return &closeWriteConn{
		Conn:        hijacked,
		ReaderFrom:  hijacked,
		closeWriter: writer,
	}
}
