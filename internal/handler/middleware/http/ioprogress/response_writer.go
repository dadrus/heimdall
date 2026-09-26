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
	"bufio"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/rs/zerolog"
)

const defaultMaxWriteChunk = 64 * 1024

type flushErrorWriter interface {
	FlushError() error
}

type responseWriter struct {
	http.ResponseWriter

	deadlines deadlineTracker
	log       *zerolog.Logger

	unsupported  bool
	needsRestore bool
	hijacked     bool
}

func (w *responseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *responseWriter) WriteHeader(code int) {
	w.armDeadline()
	w.ResponseWriter.WriteHeader(code)
	w.recordTransfer(0)
	w.restoreDeadline()
}

func (w *responseWriter) Write(data []byte) (int, error) {
	if len(data) == 0 {
		w.armDeadline()
		written, err := w.ResponseWriter.Write(data)
		w.recordTransfer(written)
		w.restoreDeadline()

		return written, err
	}

	var total int

	for len(data) > 0 {
		chunk := data
		if len(chunk) > defaultMaxWriteChunk {
			chunk = chunk[:defaultMaxWriteChunk]
		}

		w.armDeadline()
		written, err := w.ResponseWriter.Write(chunk)
		w.recordTransfer(written)
		total += written

		if err != nil {
			w.restoreDeadline()

			return total, err
		}

		if written != len(chunk) {
			w.restoreDeadline()

			return total, io.ErrShortWrite
		}

		data = data[written:]
	}

	w.restoreDeadline()

	return total, nil
}

func (w *responseWriter) armDeadline() {
	if w.unsupported {
		return
	}

	if err := http.NewResponseController(w.ResponseWriter).
		SetWriteDeadline(w.deadlines.nextDeadline(time.Now())); err != nil {
		w.unsupported = true
		w.log.Debug().Err(err).Msg("Could not set response write deadline")

		return
	}

	w.needsRestore = true
}

func (w *responseWriter) restoreDeadline() {
	if !w.needsRestore {
		return
	}

	if err := http.NewResponseController(w.ResponseWriter).
		SetWriteDeadline(w.deadlines.hardDeadline()); err != nil {
		w.log.Debug().Err(err).Msg("Could not restore response write deadline")

		return
	}

	w.needsRestore = false
}

func (w *responseWriter) recordTransfer(transferred int) {
	w.deadlines.recordTransfer(transferred)
}

func (w *responseWriter) writeString(data string) (int, error) {
	stringWriter := w.ResponseWriter.(io.StringWriter) //nolint:forcetypeassert

	if len(data) == 0 {
		w.armDeadline()
		written, err := stringWriter.WriteString(data)
		w.recordTransfer(written)
		w.restoreDeadline()

		return written, err
	}

	var total int

	for len(data) > 0 {
		chunk := data
		if len(chunk) > defaultMaxWriteChunk {
			chunk = chunk[:defaultMaxWriteChunk]
		}

		w.armDeadline()
		written, err := stringWriter.WriteString(chunk)
		w.recordTransfer(written)
		total += written

		if err != nil {
			w.restoreDeadline()

			return total, err
		}

		if written != len(chunk) {
			w.restoreDeadline()

			return total, io.ErrShortWrite
		}

		data = data[written:]
	}

	w.restoreDeadline()

	return total, nil
}

func (w *responseWriter) readFrom(src io.Reader) (int64, error) {
	readerFrom := w.ResponseWriter.(io.ReaderFrom) //nolint:forcetypeassert
	limited := io.LimitedReader{R: src}
	var total int64

	for {
		limited.N = defaultMaxWriteChunk
		w.armDeadline()
		read, err := readerFrom.ReadFrom(&limited)
		w.recordTransfer(int(read))
		total += read

		if err != nil {
			w.restoreDeadline()

			return total, err
		}

		if read < defaultMaxWriteChunk {
			w.restoreDeadline()

			return total, nil
		}
	}
}

func (w *responseWriter) flush() {
	w.armDeadline()

	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	} else {
		_ = w.ResponseWriter.(flushErrorWriter).FlushError() //nolint:forcetypeassert
	}

	w.recordTransfer(0)
	w.restoreDeadline()
}

func (w *responseWriter) flushError() error {
	w.armDeadline()

	var err error
	if flusher, ok := w.ResponseWriter.(flushErrorWriter); ok {
		err = flusher.FlushError()
	} else {
		w.ResponseWriter.(http.Flusher).Flush() //nolint:forcetypeassert
	}

	w.recordTransfer(0)
	w.restoreDeadline()

	return err
}

func (w *responseWriter) hijack() (net.Conn, *bufio.ReadWriter, error) {
	// Hijack may flush buffered HTTP/1 response data before it transfers the
	// connection to the caller, so that operation still belongs to the response
	// write policy. Once the handoff succeeds, clear the write deadline directly
	// on the returned connection and never re-arm response policy afterwards.
	w.armDeadline()
	con, rw, err := w.ResponseWriter.(http.Hijacker).Hijack() //nolint:forcetypeassert
	w.recordTransfer(0)

	if err != nil {
		w.restoreDeadline()

		return con, rw, err
	}

	w.hijacked = true
	w.needsRestore = false

	if con != nil {
		if err := con.SetWriteDeadline(time.Time{}); err != nil {
			w.log.Debug().Err(err).Msg("Could not clear hijacked connection write deadline")
		}
	}

	return con, rw, nil
}

func (w *responseWriter) push(target string, opts *http.PushOptions) error {
	return w.ResponseWriter.(http.Pusher).Push(target, opts) //nolint:forcetypeassert
}

func (w *responseWriter) finishRequest() {
	if w.hijacked {
		return
	}

	// ResponseWriter writes may be buffered by net/http for both HTTP/1 and
	// HTTP/2. Arm a fresh deadline immediately before returning to the server so
	// its final buffered flush is protected as well. The server owns cleanup once
	// the handler has returned and the response/stream is finished.
	w.armDeadline()
}
