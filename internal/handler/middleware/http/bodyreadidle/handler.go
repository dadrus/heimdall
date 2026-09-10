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

package bodyreadidle

import (
	"io"
	"net/http"
	"time"
)

type readIdleBody struct {
	io.ReadCloser

	controller *http.ResponseController
	timeout    time.Duration
}

func (b *readIdleBody) Read(data []byte) (int, error) {
	if err := b.controller.SetReadDeadline(time.Now().Add(b.timeout)); err != nil {
		return 0, err
	}

	read, readErr := b.ReadCloser.Read(data)
	if err := b.controller.SetReadDeadline(time.Time{}); err != nil && readErr == nil {
		return read, err
	}

	return read, readErr
}

// New returns a middleware that limits how long an active request body read
// may wait without progress. A timeout of zero disables the limit.
func New(timeout time.Duration) func(http.Handler) http.Handler {
	if timeout == 0 {
		return func(next http.Handler) http.Handler {
			return next
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			if req.Body == nil || req.Body == http.NoBody {
				next.ServeHTTP(rw, req)

				return
			}

			req.Body = &readIdleBody{
				ReadCloser: req.Body,
				controller: http.NewResponseController(rw),
				timeout:    timeout,
			}

			next.ServeHTTP(rw, req)
		})
	}
}
