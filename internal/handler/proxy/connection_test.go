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
	"io"
	"net"
	"sync/atomic"
	"time"
)

type testTunnelConnection struct {
	closeCalls atomic.Int32
	closeErr   error
}

type capabilityTunnelConn struct {
	testTunnelConnection

	closeWriteCalls atomic.Int32
	readFromCalls   atomic.Int32
}

func (*testTunnelConnection) Read([]byte) (int, error) { return 0, io.EOF }
func (*testTunnelConnection) Write(data []byte) (int, error) {
	return len(data), nil
}

func (c *testTunnelConnection) Close() error {
	c.closeCalls.Add(1)

	return c.closeErr
}

func (*capabilityTunnelConn) LocalAddr() net.Addr              { return nil }
func (*capabilityTunnelConn) RemoteAddr() net.Addr             { return nil }
func (*capabilityTunnelConn) SetDeadline(time.Time) error      { return nil }
func (*capabilityTunnelConn) SetReadDeadline(time.Time) error  { return nil }
func (*capabilityTunnelConn) SetWriteDeadline(time.Time) error { return nil }
func (c *capabilityTunnelConn) CloseWrite() error {
	c.closeWriteCalls.Add(1)

	return nil
}

func (c *capabilityTunnelConn) ReadFrom(src io.Reader) (int64, error) {
	c.readFromCalls.Add(1)

	return io.Copy(io.Discard, src)
}
