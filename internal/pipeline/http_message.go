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

package pipeline

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
)

var ErrHTTPMessageBodyTooLarge = errors.New(
	"http message body exceeds configured maximum size",
)

type HTTPMessage struct {
	Context   context.Context //nolint:containedctx
	Method    string
	Authority string
	URL       *url.URL
	Header    http.Header
	Body      func() (io.ReadCloser, error)
}

type HTTPMessageFinalizer struct {
	fn          func(*HTTPMessage) (http.Header, error)
	maxBodySize int64
}

func NewHTTPMessageFinalizer(
	maxBodySize int64,
	fn func(*HTTPMessage) (http.Header, error),
) HTTPMessageFinalizer {
	return HTTPMessageFinalizer{fn: fn, maxBodySize: maxBodySize}
}

func (f HTTPMessageFinalizer) Finalize(msg *HTTPMessage) (http.Header, error) {
	return f.fn(msg)
}

func (f HTTPMessageFinalizer) MaxBodySize() int64 {
	return f.maxBodySize
}

type HTTPMessageFinalizerRegistry interface {
	AddHTTPMessageFinalizerForUpstream(finalizer HTTPMessageFinalizer)
	HTTPMessageFinalizersForUpstream() []HTTPMessageFinalizer
}

type HTTPMessageOptions struct {
	MaxBodySize int64
}

type HTTPMessageOption func(*HTTPMessageOptions)

func WithMaxHTTPMessageBodySize(maxBodySize int64) HTTPMessageOption {
	return func(opts *HTTPMessageOptions) {
		opts.MaxBodySize = maxBodySize
	}
}

func NewHTTPMessageOptions(options ...HTTPMessageOption) HTTPMessageOptions {
	var opts HTTPMessageOptions
	for _, option := range options {
		option(&opts)
	}

	return opts
}

type HTTPMessageProvider interface {
	HTTPMessage(options ...HTTPMessageOption) (*HTTPMessage, error)
}

func HTTPMessageFromRequest(ctx context.Context, req *Request, options ...HTTPMessageOption) (*HTTPMessage, error) {
	if provider, ok := req.RequestFunctions.(HTTPMessageProvider); ok {
		return provider.HTTPMessage(options...)
	}

	httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL.String(), nil)
	if err != nil {
		return nil, err
	}

	for name, value := range req.Headers() {
		if name == "Host" {
			httpReq.Host = value

			continue
		}

		httpReq.Header.Set(name, value)
	}

	if len(httpReq.Host) == 0 {
		httpReq.Host = req.URL.Host
	}

	return &HTTPMessage{
		Context:   ctx,
		Method:    req.Method,
		Authority: httpReq.Host,
		URL:       new(req.URL.URL),
		Header:    httpReq.Header.Clone(),
		Body:      func() (io.ReadCloser, error) { return http.NoBody, nil },
	}, nil
}

func HTTPMessageFromHTTPRequest(req *http.Request, options ...HTTPMessageOption) *HTTPMessage {
	var (
		getBody      func() (io.ReadCloser, error)
		bodySnapshot []byte
	)

	opts := NewHTTPMessageOptions(options...)

	switch {
	case req.GetBody != nil:
		getBody = req.GetBody
	case req.Body == nil || req.Body == http.NoBody:
		getBody = func() (io.ReadCloser, error) { return http.NoBody, nil }
	default:
		getBody = func() (io.ReadCloser, error) {
			if len(bodySnapshot) != 0 {
				return io.NopCloser(bytes.NewReader(bodySnapshot)), nil
			}

			body, err := readHTTPMessageBody(req.Body, opts.MaxBodySize)
			if err != nil {
				_ = req.Body.Close()

				return nil, err
			}

			if err := req.Body.Close(); err != nil {
				return nil, err
			}

			bodySnapshot = body
			req.Body = io.NopCloser(bytes.NewReader(bodySnapshot))

			return io.NopCloser(bytes.NewReader(bodySnapshot)), nil
		}
	}

	return &HTTPMessage{
		Context:   req.Context(),
		Method:    req.Method,
		Authority: req.Host,
		URL:       req.URL,
		Header:    req.Header.Clone(),
		Body:      getBody,
	}
}

func ApplyHTTPMessageFinalizers(msg *HTTPMessage, finalizers ...HTTPMessageFinalizer) (http.Header, error) {
	header := msg.Header.Clone()

	for _, finalizer := range finalizers {
		msg.Header = header

		signed, err := finalizer.Finalize(msg)
		if err != nil {
			return nil, err
		}

		header = signed.Clone()
	}

	return header, nil
}

func MaxHTTPMessageFinalizerBodySize(finalizers ...HTTPMessageFinalizer) int64 {
	var maxBodySize int64

	for _, finalizer := range finalizers {
		if finalizer.MaxBodySize() > maxBodySize {
			maxBodySize = finalizer.MaxBodySize()
		}
	}

	return maxBodySize
}

func readHTTPMessageBody(body io.Reader, maxBodySize int64) ([]byte, error) {
	var (
		buf    bytes.Buffer
		reader = body
	)

	if maxBodySize > 0 && maxBodySize < math.MaxInt64 {
		reader = io.LimitReader(body, maxBodySize+1)
	}

	if _, err := buf.ReadFrom(reader); err != nil {
		return nil, err
	}

	if maxBodySize > 0 && int64(buf.Len()) > maxBodySize {
		return nil, ErrHTTPMessageBodyTooLarge
	}

	return buf.Bytes(), nil
}

func HTTPMessageBodyWithMaxSize(
	body func() (io.ReadCloser, error),
	maxBodySize int64,
) func() (io.ReadCloser, error) {
	return func() (io.ReadCloser, error) {
		rc, err := body()
		if err != nil {
			return nil, err
		}

		return &maxBytesReadCloser{
			rc:        rc,
			remaining: maxBodySize,
		}, nil
	}
}

type maxBytesReadCloser struct {
	rc        io.ReadCloser
	remaining int64
}

func (r *maxBytesReadCloser) Read(chunk []byte) (int, error) {
	if r.remaining == 0 {
		var b [1]byte

		n, err := r.rc.Read(b[:])
		if n > 0 {
			if closeErr := r.rc.Close(); closeErr != nil {
				return 0, fmt.Errorf("%w: %w", ErrHTTPMessageBodyTooLarge, closeErr)
			}

			return 0, ErrHTTPMessageBodyTooLarge
		}

		return 0, err
	}

	if int64(len(chunk)) > r.remaining {
		chunk = chunk[:int(r.remaining)]
	}

	n, err := r.rc.Read(chunk)
	r.remaining -= int64(n)

	return n, err
}

func (r *maxBytesReadCloser) Close() error {
	return r.rc.Close()
}
