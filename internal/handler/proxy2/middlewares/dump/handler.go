package dump

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"

	"github.com/felixge/httpsnoop"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/x/stringx"
)

var (
	excludedHeadersNoBody = map[string]bool{"Content-Length": true, "Transfer-Encoding": true} //nolint:gochecknoglobals
	crlf                  = []byte("\r\n")                                                     //nolint:gochecknoglobals
)

func New() func(http.Handler) http.Handler { // nolint: funlen, gocognit, cyclop
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			logger := zerolog.Ctx(req.Context())

			if logger.GetLevel() != zerolog.TraceLevel {
				next.ServeHTTP(rw, req)

				return
			}

			if dump, err := httputil.DumpRequest(req, true); err == nil {
				logger.Trace().Msg("Request: \n" + stringx.ToString(dump))
			} else {
				logger.Trace().Err(err).Msg("Failed dumping request")
			}

			var (
				wroteHeader          bool
				hijacked             bool
				contentLengthWritten bool
				buffer               bytes.Buffer
				statusBuf            [3]byte
			)

			next.ServeHTTP(httpsnoop.Wrap(rw, httpsnoop.Hooks{
				Hijack: func(hijackFunc httpsnoop.HijackFunc) httpsnoop.HijackFunc {
					return func() (net.Conn, *bufio.ReadWriter, error) {
						hijacked = true

						logger.Trace().Msg("Response: \n" + stringx.ToString(buffer.Bytes()))

						// reset the buffer entirely to be consumed by GC
						buffer = bytes.Buffer{}

						return rw.(http.Hijacker).Hijack() // nolint: forcetypeassert
					}
				},
				WriteHeader: func(headerFunc httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
					return func(code int) {
						if !wroteHeader {
							writeStatusLine(&buffer, protoAtLeast(req, 1, 1), code, statusBuf[:])

							if code >= 100 && code <= 199 && code != http.StatusSwitchingProtocols {
								rw.Header().WriteSubset(&buffer, excludedHeadersNoBody) //nolint:errcheck
								buffer.Write(crlf)
							} else {
								rw.Header().Write(&buffer) //nolint:errcheck

								if len(rw.Header().Get("Content-Length")) != 0 {
									buffer.Write(crlf)
								}
							}

							wroteHeader = true
						}

						rw.WriteHeader(code)
					}
				},
				Write: func(writeFunc httpsnoop.WriteFunc) httpsnoop.WriteFunc {
					return func(data []byte) (int, error) {
						if !hijacked && !wroteHeader {
							rw.WriteHeader(http.StatusOK)

							writeStatusLine(&buffer, protoAtLeast(req, 1, 1), http.StatusOK, statusBuf[:])
							rw.Header().Write(&buffer) //nolint:errcheck
						}

						if !hijacked {
							if len(rw.Header().Get("Content-Length")) == 0 && !contentLengthWritten {
								http.Header{"Content-Length": []string{strconv.Itoa(len(data))}}.Write(&buffer) //nolint:errcheck
								buffer.Write(crlf)
								contentLengthWritten = true
							}

							buffer.Write(data)
						}

						return rw.Write(data)
					}
				},
			}), req)

			if !hijacked {
				// build message from the collected data
				logger.Trace().Msg("Response: \n" + stringx.ToString(buffer.Bytes()))
			}
		})
	}
}

func protoAtLeast(req *http.Request, major, minor int) bool {
	return req.ProtoMajor > major ||
		req.ProtoMajor == major && req.ProtoMinor >= minor
}

func writeStatusLine(bw *bytes.Buffer, is11 bool, code int, scratch []byte) {
	if is11 {
		bw.WriteString("HTTP/1.1 ")
	} else {
		bw.WriteString("HTTP/1.0 ")
	}

	if text := http.StatusText(code); text != "" {
		bw.Write(strconv.AppendInt(scratch[:0], int64(code), 10)) //nolint:gomnd
		bw.WriteByte(' ')
		bw.WriteString(text)
		bw.WriteString("\r\n")
	} else {
		fmt.Fprintf(bw, "%03d status code %d\r\n", code, code)
	}
}
