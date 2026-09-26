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

package ioprogress

import (
	"io"
	"net/http"
	"time"
)

type bodyReadCloser struct {
	io.ReadCloser

	rw          http.ResponseWriter
	deadlines   deadlineTracker
	unsupported bool
}

func (b *bodyReadCloser) Read(data []byte) (int, error) {
	deadlineSet := false
	if !b.unsupported {
		// Set the progress deadline for the upcoming blocking Read.
		if err := http.NewResponseController(b.rw).SetReadDeadline(b.deadlines.nextDeadline(time.Now())); err != nil {
			b.unsupported = true
		} else {
			deadlineSet = true
		}
	}

	read, readErr := b.ReadCloser.Read(data)

	// Account read bytes when calculating the next progress deadline.
	b.deadlines.recordTransfer(read)

	if deadlineSet {
		// Replace the deadline set for this Read with the absolute hard deadline.
		// If no hard deadline is configured, hardDeadline() returns the zero time,
		// which clears the read deadline.
		if err := http.NewResponseController(b.rw).SetReadDeadline(b.deadlines.hardDeadline()); err != nil {
			b.unsupported = true
		}
	}

	return read, readErr
}

func wrapRequestBody(
	req *http.Request,
	rw http.ResponseWriter,
	hardTimeout time.Duration,
	idleTimeout time.Duration,
	minRate int64,
) {
	if req.Body == nil || req.Body == http.NoBody {
		return
	}

	req.Body = &bodyReadCloser{
		ReadCloser: req.Body,
		rw:         rw,
		deadlines:  newDeadlineTracker(hardTimeout, idleTimeout, minRate, time.Now()),
	}
}
