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

package dump

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"

	"github.com/felixge/httpsnoop"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/x/stringx"
)

var crlf = []byte("\r\n") //nolint:gochecknoglobals

type traceWriter struct {
	l    *zerolog.Logger
	done bool
}

func (tw *traceWriter) Write(data []byte) (int, error) {
	// only the very first write is relevant for hijacked connections
	// afterward, the transmission of payloads happens
	// actually, the above said transmission is done directly on the connection
	// and not using the buffer. So we'll actually be called only once
	if tw.done {
		return len(data), nil
	}

	tw.l.Trace().Msgf("Response: %s\n", stringx.ToString(data))
	tw.done = true

	return len(data), nil
}

func New() func(http.Handler) http.Handler { // nolint: funlen, gocognit, cyclop
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			logger := zerolog.Ctx(req.Context())

			if logger.GetLevel() != zerolog.TraceLevel {
				next.ServeHTTP(rw, req)

				return
			}

			contentType := req.Header.Get("Content-Type")
			// don't dump the body if content type is some sort of stream
			if dump, err := httputil.DumpRequest(req,
				req.ContentLength != 0 &&
					!strings.Contains(contentType, "stream") &&
					!strings.Contains(contentType, "application/x-ndjson")); err == nil {
				logger.Trace().Msgf("Request: %s\n", stringx.ToString(dump))
			} else {
				logger.Trace().Err(err).Msg("Failed dumping request")
			}

			var (
				wroteHeader bool
				hijacked    bool
				flushed     bool
				buffer      bytes.Buffer
				statusBuf   [3]byte
			)

			next.ServeHTTP(httpsnoop.Wrap(rw, httpsnoop.Hooks{
				Hijack: func(hijack httpsnoop.HijackFunc) httpsnoop.HijackFunc {
					return func() (net.Conn, *bufio.ReadWriter, error) {
						hijacked = true
						buffer.Reset()
						buffer = bytes.Buffer{}

						con, _, err := hijack()
						if err != nil {
							return nil, nil, err
						}

						return con,
							bufio.NewReadWriter(
								bufio.NewReader(con),
								bufio.NewWriter(io.MultiWriter(con, &traceWriter{l: logger}))),
							nil
					}
				},
				WriteHeader: func(writeHeader httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
					return func(code int) {
						if !wroteHeader {
							writeStatusLine(&buffer, req.Proto, code, statusBuf[:])
							rw.Header().Write(&buffer) //nolint:errcheck

							if len(rw.Header().Get("Content-Length")) != 0 {
								buffer.Write(crlf)
							}

							wroteHeader = true
						}

						writeHeader(code)
					}
				},
				Write: func(write httpsnoop.WriteFunc) httpsnoop.WriteFunc {
					return func(data []byte) (int, error) {
						if !wroteHeader {
							writeStatusLine(&buffer, req.Proto, http.StatusOK, statusBuf[:])
							rw.Header().Write(&buffer) //nolint:errcheck

							rw.WriteHeader(http.StatusOK)
						}

						buffer.Write(data)

						return write(data)
					}
				},
				Flush: func(flush httpsnoop.FlushFunc) httpsnoop.FlushFunc {
					return func() {
						if !flushed {
							logger.Trace().Msgf("Response: %s\n", stringx.ToString(buffer.Bytes()))
							flushed = true

							buffer.Reset()
							buffer = bytes.Buffer{}
						}

						flush()
					}
				},
			}), req)

			if !hijacked && !flushed {
				// build message from the collected data
				logger.Trace().Msgf("Response: %s\n", stringx.ToString(buffer.Bytes()))
			}

			buffer.Reset()
		})
	}
}

func writeStatusLine(bw *bytes.Buffer, proto string, code int, scratch []byte) {
	bw.WriteString(proto + " ")

	if text := http.StatusText(code); text != "" {
		bw.Write(strconv.AppendInt(scratch[:0], int64(code), 10)) //nolint:mnd
		bw.WriteByte(' ')
		bw.WriteString(text)
		bw.WriteString("\r\n")
	} else {
		fmt.Fprintf(bw, "%03d status code %d\r\n", code, code)
	}
}
