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

	"github.com/felixge/httpsnoop"
	"github.com/rs/zerolog"
)

type responseWriterCapabilities uint8

const (
	capabilityFlusher responseWriterCapabilities = 1 << iota
	capabilityHijacker
	capabilityReaderFrom
	capabilityPusher
	capabilityStringWriter
	capabilityCloseNotifier
)

type flusherAdapter struct{ writer *responseWriter }

func (adapter flusherAdapter) Flush()            { adapter.writer.flush() }
func (adapter flusherAdapter) FlushError() error { return adapter.writer.flushError() }

type hijackerAdapter struct{ writer *responseWriter }

func (adapter hijackerAdapter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return adapter.writer.hijack()
}

type readerFromAdapter struct{ writer *responseWriter }

func (adapter readerFromAdapter) ReadFrom(src io.Reader) (int64, error) {
	return adapter.writer.readFrom(src)
}

type pusherAdapter struct{ writer *responseWriter }

func (adapter pusherAdapter) Push(target string, opts *http.PushOptions) error {
	return adapter.writer.push(target, opts)
}

type stringWriterAdapter struct{ writer *responseWriter }

func (adapter stringWriterAdapter) WriteString(data string) (int, error) {
	return adapter.writer.writeString(data)
}

type closeNotifierAdapter struct{ writer *responseWriter }

func (adapter closeNotifierAdapter) CloseNotify() <-chan bool {
	return adapter.writer.ResponseWriter.(http.CloseNotifier).CloseNotify() //nolint:forcetypeassert
}

// Static adapter combinations used on the hot path.
//
// F = http.Flusher
// H = http.Hijacker
// R = io.ReaderFrom
// P = http.Pusher
// S = io.StringWriter
// N = http.CloseNotifier
//
// These are the interface sets exposed by the net/http HTTP/1 and HTTP/2
// response writers plus the small synthetic combinations used by tests and
// benchmarks. Less common combinations fall back to httpsnoop to preserve
// their exact interface set without putting hook allocations on the server hot
// path.
type adapterF struct {
	responseWriter
	flusherAdapter
}

type adapterFHRS struct {
	responseWriter
	flusherAdapter
	hijackerAdapter
	readerFromAdapter
	stringWriterAdapter
}

type adapterFHRSN struct {
	responseWriter
	flusherAdapter
	hijackerAdapter
	readerFromAdapter
	stringWriterAdapter
	closeNotifierAdapter
}

type adapterFPS struct {
	responseWriter
	flusherAdapter
	pusherAdapter
	stringWriterAdapter
}

type adapterFPSN struct {
	responseWriter
	flusherAdapter
	pusherAdapter
	stringWriterAdapter
	closeNotifierAdapter
}

type adapterFSN struct {
	responseWriter
	flusherAdapter
	stringWriterAdapter
	closeNotifierAdapter
}

type adapterFHRPS struct {
	responseWriter
	flusherAdapter
	hijackerAdapter
	readerFromAdapter
	pusherAdapter
	stringWriterAdapter
}

func detectResponseWriterCapabilities(rw http.ResponseWriter) responseWriterCapabilities {
	var capabilities responseWriterCapabilities

	if _, ok := rw.(http.Flusher); ok {
		capabilities |= capabilityFlusher
	} else if _, ok := rw.(flushErrorWriter); ok {
		capabilities |= capabilityFlusher
	}
	if _, ok := rw.(http.Hijacker); ok {
		capabilities |= capabilityHijacker
	}
	if _, ok := rw.(io.ReaderFrom); ok {
		capabilities |= capabilityReaderFrom
	}
	if _, ok := rw.(http.Pusher); ok {
		capabilities |= capabilityPusher
	}
	if _, ok := rw.(io.StringWriter); ok {
		capabilities |= capabilityStringWriter
	}
	if _, ok := rw.(http.CloseNotifier); ok { //nolint:staticcheck
		capabilities |= capabilityCloseNotifier
	}

	return capabilities
}

//nolint:funlen
func wrapResponseWriter(
	rw http.ResponseWriter,
	deadlines deadlineTracker,
	log *zerolog.Logger,
) (http.ResponseWriter, *responseWriter) {
	// Keep the responseWriter construction inside the selected adapter. A shared
	// local state escapes independently because some branches return its address,
	// adding a second allocation to the hot-path adapters.
	switch detectResponseWriterCapabilities(rw) {
	case 0:
		wrapped := &responseWriter{
			ResponseWriter: rw,
			deadlines:      deadlines,
			log:            log,
		}

		return wrapped, wrapped
	case capabilityFlusher:
		wrapped := &adapterF{
			ResponseWriter: rw,
			deadlines:      deadlines,
			log:            log,
		}
		wrapped.flusherAdapter.writer = &wrapped.responseWriter

		return wrapped, &wrapped.responseWriter
	case capabilityFlusher | capabilityHijacker | capabilityReaderFrom | capabilityStringWriter:
		wrapped := &adapterFHRS{
			ResponseWriter: rw,
			deadlines:      deadlines,
			log:            log,
		}
		bindFHRS(&wrapped.responseWriter, &wrapped.flusherAdapter, &wrapped.hijackerAdapter,
			&wrapped.readerFromAdapter, &wrapped.stringWriterAdapter)

		return wrapped, &wrapped.responseWriter
	case capabilityFlusher | capabilityHijacker | capabilityReaderFrom | capabilityStringWriter | capabilityCloseNotifier:
		wrapped := &adapterFHRSN{
			ResponseWriter: rw,
			deadlines:      deadlines,
			log:            log,
		}
		bindFHRS(&wrapped.responseWriter, &wrapped.flusherAdapter, &wrapped.hijackerAdapter,
			&wrapped.readerFromAdapter, &wrapped.stringWriterAdapter)
		wrapped.closeNotifierAdapter.writer = &wrapped.responseWriter

		return wrapped, &wrapped.responseWriter
	case capabilityFlusher | capabilityPusher | capabilityStringWriter:
		wrapped := &adapterFPS{
			ResponseWriter: rw,
			deadlines:      deadlines,
			log:            log,
		}
		bindFPS(&wrapped.responseWriter, &wrapped.flusherAdapter, &wrapped.pusherAdapter, &wrapped.stringWriterAdapter)

		return wrapped, &wrapped.responseWriter
	case capabilityFlusher | capabilityPusher | capabilityStringWriter | capabilityCloseNotifier:
		wrapped := &adapterFPSN{
			ResponseWriter: rw,
			deadlines:      deadlines,
			log:            log,
		}
		bindFPS(&wrapped.responseWriter, &wrapped.flusherAdapter, &wrapped.pusherAdapter, &wrapped.stringWriterAdapter)
		wrapped.closeNotifierAdapter.writer = &wrapped.responseWriter

		return wrapped, &wrapped.responseWriter
	case capabilityFlusher | capabilityStringWriter | capabilityCloseNotifier:
		wrapped := &adapterFSN{
			ResponseWriter: rw,
			deadlines:      deadlines,
			log:            log,
		}
		wrapped.flusherAdapter.writer = &wrapped.responseWriter
		wrapped.stringWriterAdapter.writer = &wrapped.responseWriter
		wrapped.closeNotifierAdapter.writer = &wrapped.responseWriter

		return wrapped, &wrapped.responseWriter
	case capabilityFlusher | capabilityHijacker | capabilityReaderFrom | capabilityPusher | capabilityStringWriter:
		wrapped := &adapterFHRPS{
			ResponseWriter: rw,
			deadlines:      deadlines,
			log:            log,
		}
		bindFHRS(&wrapped.responseWriter, &wrapped.flusherAdapter, &wrapped.hijackerAdapter,
			&wrapped.readerFromAdapter, &wrapped.stringWriterAdapter)
		wrapped.pusherAdapter.writer = &wrapped.responseWriter

		return wrapped, &wrapped.responseWriter
	default:
		state := &responseWriter{
			ResponseWriter: rw,
			deadlines:      deadlines,
			log:            log,
		}

		return wrapFallback(rw, state), state
	}
}

func bindFHRS(
	state *responseWriter,
	flusher *flusherAdapter,
	hijacker *hijackerAdapter,
	readerFrom *readerFromAdapter,
	stringWriter *stringWriterAdapter,
) {
	flusher.writer = state
	hijacker.writer = state
	readerFrom.writer = state
	stringWriter.writer = state
}

func bindFPS(
	state *responseWriter,
	flusher *flusherAdapter,
	pusher *pusherAdapter,
	stringWriter *stringWriterAdapter,
) {
	flusher.writer = state
	pusher.writer = state
	stringWriter.writer = state
}

func wrapFallback(rw http.ResponseWriter, state *responseWriter) http.ResponseWriter {
	return httpsnoop.Wrap(rw, httpsnoop.Hooks{
		WriteHeader: func(httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
			return state.WriteHeader
		},
		Write: func(httpsnoop.WriteFunc) httpsnoop.WriteFunc {
			return state.Write
		},
		WriteString: func(httpsnoop.WriteStringFunc) httpsnoop.WriteStringFunc {
			return state.writeString
		},
		ReadFrom: func(httpsnoop.ReadFromFunc) httpsnoop.ReadFromFunc {
			return state.readFrom
		},
		Flush: func(httpsnoop.FlushFunc) httpsnoop.FlushFunc {
			return state.flush
		},
		FlushError: func(httpsnoop.FlushErrorFunc) httpsnoop.FlushErrorFunc {
			return state.flushError
		},
		Hijack: func(httpsnoop.HijackFunc) httpsnoop.HijackFunc {
			return state.hijack
		},
	})
}
