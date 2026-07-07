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
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPMessageFromRequestFallbackIsBodyless(t *testing.T) {
	t.Parallel()

	rawURL, err := url.Parse("https://api.example.test/foo?bar=baz")
	require.NoError(t, err)

	msg, err := HTTPMessageFromRequest(t.Context(), &Request{
		Method: http.MethodPost,
		URL: &URL{
			URL: *rawURL,
		},
		RequestFunctions: staticRequestFunctions{
			headers: map[string]string{
				"Host":         "signed.example.test",
				"Content-Type": "application/json",
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, http.MethodPost, msg.Method)
	assert.Equal(t, "signed.example.test", msg.Authority)
	assert.Equal(t, "https://api.example.test/foo?bar=baz", msg.URL.String())
	assert.Equal(t, "application/json", msg.Header.Get("Content-Type"))

	body, err := msg.Body()
	require.NoError(t, err)

	data, err := io.ReadAll(body)
	require.NoError(t, err)
	assert.Empty(t, data)
}

func TestApplyHTTPMessageFinalizersComposesSignatureHeadersInOrder(t *testing.T) {
	t.Parallel()

	rawURL, err := url.Parse("https://api.example.test/foo")
	require.NoError(t, err)

	msg := &HTTPMessage{
		Context:   t.Context(),
		Method:    http.MethodPost,
		Authority: rawURL.Host,
		URL:       rawURL,
		Header: http.Header{
			"Content-Type": {"application/json"},
		},
		Body: func() (io.ReadCloser, error) { return http.NoBody, nil },
	}

	first := NewHTTPMessageFinalizer(4, func(msg *HTTPMessage) (http.Header, error) {
		assert.Equal(t, "application/json", msg.Header.Get("Content-Type"))
		assert.Empty(t, msg.Header.Values("Signature"))

		header := msg.Header.Clone()
		header.Add("Signature-Input", `sig-a=("@method" "@authority" "@path")`)
		header.Add("Signature", "sig-a=:first:")

		return header, nil
	})

	second := NewHTTPMessageFinalizer(8, func(msg *HTTPMessage) (http.Header, error) {
		assert.Equal(t, []string{"sig-a=:first:"}, msg.Header.Values("Signature"))
		assert.Equal(t, []string{`sig-a=("@method" "@authority" "@path")`}, msg.Header.Values("Signature-Input"))

		header := msg.Header.Clone()
		header.Add("Signature-Input", `sig-b=("@method" "@authority" "@path")`)
		header.Add("Signature", "sig-b=:second:")

		return header, nil
	})

	header, err := ApplyHTTPMessageFinalizers(msg, first, second)

	require.NoError(t, err)
	assert.Equal(t, []string{"sig-a=:first:", "sig-b=:second:"}, header.Values("Signature"))
	assert.Equal(t,
		[]string{
			`sig-a=("@method" "@authority" "@path")`,
			`sig-b=("@method" "@authority" "@path")`,
		},
		header.Values("Signature-Input"),
	)
	assert.Equal(t, int64(8), MaxHTTPMessageFinalizerBodySize(first, second))
}

type staticRequestFunctions struct {
	headers map[string]string
}

func (f staticRequestFunctions) Header(name string) string {
	return f.headers[name]
}

func (staticRequestFunctions) Cookie(string) string {
	return ""
}

func (f staticRequestFunctions) Headers() map[string]string {
	return f.headers
}

func (staticRequestFunctions) Body() any {
	return ""
}
