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

package httpx

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsStreamingContentType(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		contentType string
		expected    bool
	}{
		"empty":                        {contentType: "", expected: false},
		"json":                         {contentType: "application/json", expected: false},
		"event stream":                 {contentType: "text/event-stream", expected: true},
		"event stream with parameters": {contentType: "text/event-stream; charset=utf-8", expected: true},
		"case insensitive stream":      {contentType: "TEXT/EVENT-STREAM", expected: true},
		"octet stream":                 {contentType: "application/octet-stream", expected: true},
		"ndjson":                       {contentType: "application/x-ndjson", expected: true},
		"native grpc":                  {contentType: "application/grpc", expected: true},
		"native grpc with parameters":  {contentType: "application/grpc; charset=utf-8", expected: true},
		"native grpc proto":            {contentType: "application/grpc+proto", expected: true},
		"native grpc json":             {contentType: "application/grpc+json", expected: true},
		"grpc web":                     {contentType: "application/grpc-web", expected: false},
		"grpc web proto":               {contentType: "application/grpc-web+proto", expected: false},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.expected, IsStreamingContentType(tc.contentType))
		})
	}
}

func TestShouldDumpRequestBody(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		contentLength int64
		contentType   string
		upgrade       string
		expected      bool
	}{
		"known regular body":     {contentLength: 42, contentType: "application/json", expected: true},
		"empty body":             {contentLength: 0, contentType: "application/json", expected: false},
		"unknown body length":    {contentLength: -1, contentType: "application/json", expected: false},
		"native grpc body":       {contentLength: 42, contentType: "application/grpc", expected: false},
		"streaming content type": {contentLength: 42, contentType: "text/event-stream", expected: false},
		"upgrade request":        {contentLength: 42, contentType: "application/json", upgrade: "websocket", expected: false},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			req := &http.Request{
				ContentLength: tc.contentLength,
				Header:        make(http.Header),
			}
			req.Header.Set("Content-Type", tc.contentType)
			req.Header.Set("Upgrade", tc.upgrade)

			assert.Equal(t, tc.expected, ShouldDumpRequestBody(req))
		})
	}
}

func TestShouldDumpResponseBody(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		contentLength int64
		contentType   string
		statusCode    int
		expected      bool
	}{
		"known regular body":     {contentLength: 42, contentType: "application/json", statusCode: http.StatusOK, expected: true},
		"empty body":             {contentLength: 0, contentType: "application/json", statusCode: http.StatusOK, expected: false},
		"unknown body length":    {contentLength: -1, contentType: "application/json", statusCode: http.StatusOK, expected: false},
		"native grpc body":       {contentLength: 42, contentType: "application/grpc", statusCode: http.StatusOK, expected: false},
		"streaming content type": {contentLength: 42, contentType: "text/event-stream", statusCode: http.StatusOK, expected: false},
		"switching protocols":    {contentLength: 42, contentType: "application/json", statusCode: http.StatusSwitchingProtocols, expected: false},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			resp := &http.Response{ //nolint:bodyclose
				StatusCode:    tc.statusCode,
				ContentLength: tc.contentLength,
				Header:        make(http.Header),
			}
			resp.Header.Set("Content-Type", tc.contentType)

			assert.Equal(t, tc.expected, ShouldDumpResponseBody(resp))
		})
	}
}
