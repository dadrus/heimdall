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

	tw.l.Trace().Msg("Response: \n" + stringx.ToString(data))
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

			if dump, err := httputil.DumpRequest(req, true); err == nil {
				logger.Trace().Msg("Request: \n" + stringx.ToString(dump))
			} else {
				logger.Trace().Err(err).Msg("Failed dumping request")
			}

			var (
				wroteHeader bool
				hijacked    bool
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
			}), req)

			if !hijacked {
				// build message from the collected data
				logger.Trace().Msg("Response: \n" + stringx.ToString(buffer.Bytes()))
			}

			buffer.Reset()
		})
	}
}

func writeStatusLine(bw *bytes.Buffer, proto string, code int, scratch []byte) {
	bw.WriteString(fmt.Sprintf("%s ", proto))

	if text := http.StatusText(code); text != "" {
		bw.Write(strconv.AppendInt(scratch[:0], int64(code), 10)) //nolint:gomnd
		bw.WriteByte(' ')
		bw.WriteString(text)
		bw.WriteString("\r\n")
	} else {
		fmt.Fprintf(bw, "%03d status code %d\r\n", code, code)
	}
}
