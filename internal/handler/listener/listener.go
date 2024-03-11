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

package listener

import (
	"crypto/tls"
	"net"
	"sync/atomic"
	"time"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/watcher"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/tlsx"
)

type conn struct {
	net.Conn

	writeTimeout  atomic.Int64
	resetDeadline atomic.Bool
	bytesWritten  atomic.Int32
}

func (c *conn) Write(data []byte) (int, error) {
	if c.resetDeadline.Load() && c.bytesWritten.Load() > 0 {
		c.bytesWritten.Store(0)

		if err := c.Conn.SetWriteDeadline(time.Now().Add(time.Duration(c.writeTimeout.Load()))); err != nil {
			return 0, err
		}
	}

	n, err := c.Conn.Write(data)
	if c.resetDeadline.Load() {
		c.bytesWritten.Add(int32(n))
	}

	return n, err
}

func (c *conn) SetDeadline(deadline time.Time) error {
	if deadline.Equal(time.Time{}) {
		c.resetDeadline.Store(false)
	} else {
		c.writeTimeout.Store(int64(time.Until(deadline)))
	}

	return c.Conn.SetDeadline(deadline)
}

func (c *conn) SetWriteDeadline(deadline time.Time) error {
	if deadline.Equal(time.Time{}) {
		c.resetDeadline.Store(false)
	} else {
		c.writeTimeout.Store(int64(time.Until(deadline)))
	}

	return c.Conn.SetWriteDeadline(deadline)
}

func (c *conn) MonitorAndResetDeadlines(flag bool) {
	c.resetDeadline.Store(flag)
}

type listener struct {
	net.Listener
}

func (l *listener) Accept() (net.Conn, error) {
	con, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return &conn{Conn: con}, nil
}

func New(network, address string, tlsConf *config.TLS, cw watcher.Watcher) (net.Listener, error) {
	listnr, err := net.Listen(network, address)
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal, "failed creating listener").
			CausedBy(err)
	}

	wrapped := &listener{Listener: listnr}

	if tlsConf != nil {
		return newTLSListener(tlsConf, wrapped, cw)
	}

	return wrapped, nil
}

func newTLSListener(tlsConf *config.TLS, listener net.Listener, cw watcher.Watcher) (net.Listener, error) {
	cfg, err := tlsx.ToTLSConfig(tlsConf,
		tlsx.WithServerAuthentication(true),
		tlsx.WithSecretsWatcher(cw),
	)
	if err != nil {
		return nil, err
	}

	return tls.NewListener(listener, cfg), nil
}
