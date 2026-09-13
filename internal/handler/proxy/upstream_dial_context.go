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
	"net"
	"time"

	"github.com/dadrus/heimdall/internal/config"
)

type idleConnectionWriter struct {
	net.Conn

	timeout time.Duration
}

func (c *idleConnectionWriter) Write(data []byte) (int, error) {
	_ = c.Conn.SetWriteDeadline(time.Now().Add(c.timeout))
	defer func() { _ = c.Conn.SetWriteDeadline(time.Time{}) }()

	return c.Conn.Write(data)
}

func newUpstreamDialContext(
	cfg config.UpstreamConnections,
) func(context.Context, string, string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout:   cfg.DialTimeout,
		KeepAlive: 30 * time.Second, //nolint:mnd
	}

	if cfg.WriteIdleTimeout <= 0 {
		return dialer.DialContext
	}

	return func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := dialer.DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}

		return &idleConnectionWriter{
			Conn:    conn,
			timeout: cfg.WriteIdleTimeout,
		}, nil
	}
}
