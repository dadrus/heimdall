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
	"crypto/rand"
	"io"
	"net/http"

	"github.com/dadrus/heimdall/internal/handler/requestcontext"
)

const webSocketCloseGoingAway = 1001

type webSocketRole uint8

const (
	webSocketServer webSocketRole = iota
	webSocketClient
)

type webSocketGoingAwayTeardownStrategy struct {
	role webSocketRole
}

func (s webSocketGoingAwayTeardownStrategy) apply(ctx context.Context, conn io.ReadWriteCloser) {
	writeDone := make(chan struct{})
	go func() {
		_ = writeWebSocketGoingAway(conn, s.role)
		close(writeDone)
	}()

	select {
	case <-writeDone:
	case <-ctx.Done():
		// Best effort only. The registry closes the owned connection after all
		// teardown strategies had a chance to run, unblocking pending writes.
	}
}

var (
	webSocketServerGoingAwayTeardownStrategy = webSocketGoingAwayTeardownStrategy{role: webSocketServer}
	webSocketClientGoingAwayTeardownStrategy = webSocketGoingAwayTeardownStrategy{role: webSocketClient}
)

func writeWebSocketGoingAway(conn io.Writer, role webSocketRole) error {
	const (
		finalCloseFrame = 0x88
		maskBit         = 0x80
		payloadSize     = 2
	)

	statusCode := [payloadSize]byte{
		byte(webSocketCloseGoingAway >> 8),   //nolint:mnd
		byte(webSocketCloseGoingAway & 0xff), //nolint:mnd
	}

	frame := []byte{
		finalCloseFrame,
		payloadSize,
		statusCode[0],
		statusCode[1],
	}

	if role == webSocketClient {
		var maskKey [4]byte
		if _, err := rand.Read(maskKey[:]); err != nil {
			return err
		}

		frame = []byte{
			finalCloseFrame,
			maskBit | payloadSize,
			maskKey[0],
			maskKey[1],
			maskKey[2],
			maskKey[3],
			statusCode[0] ^ maskKey[0],
			statusCode[1] ^ maskKey[1],
		}
	}

	written, err := conn.Write(frame)
	if err != nil {
		return err
	}

	if written != len(frame) {
		return io.ErrShortWrite
	}

	return nil
}

func isWebSocketUpgrade(req *http.Request) bool {
	return req != nil && classifyUpgrade(req) == upgradeKindWebSocket
}

func isWebSocketUpgradeResponse(res *http.Response) bool {
	if res == nil || res.StatusCode != http.StatusSwitchingProtocols || !isWebSocketUpgrade(res.Request) {
		return false
	}

	if !headerValuesContainToken(res.Header.Values("Upgrade"), "websocket") {
		return false
	}

	for option := range requestcontext.ConnectionOptions(res.Header) {
		if option == "Upgrade" {
			return true
		}
	}

	return false
}
