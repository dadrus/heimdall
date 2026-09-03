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

package requestcontext

import (
	"bytes"
	"io"
	"net/http"

	"github.com/dadrus/heimdall/internal/pipeline"
)

type netHTTPBodySource struct {
	req *http.Request
}

func (s *netHTTPBodySource) ReadRawBody() ([]byte, error) {
	if s.req == nil || s.req.Body == nil || s.req.Body == http.NoBody {
		return []byte{}, nil
	}

	body, err := io.ReadAll(s.req.Body)
	if err != nil {
		return nil, err
	}

	_ = s.req.Body.Close()
	s.req.Body = io.NopCloser(bytes.NewReader(body))

	return body, nil
}

type NetHTTPRequestContext struct {
	*RequestContext

	req        *http.Request
	bodySource netHTTPBodySource
}

func New() *NetHTTPRequestContext {
	return &NetHTTPRequestContext{
		RequestContext: NewRequestContext(),
	}
}

func (r *NetHTTPRequestContext) UpstreamRequest() pipeline.UpstreamRequest {
	return nil
}

func (r *NetHTTPRequestContext) Init(req *http.Request) {
	r.req = req
	r.bodySource.req = req

	r.RequestContext.Init(Input{
		Context:    req.Context(),
		Method:     extractMethod(req),
		URL:        extractURL(req),
		Headers:    req.Header,
		RemoteAddr: req.RemoteAddr,
		Body:       &r.bodySource,
	})
}

func (r *NetHTTPRequestContext) Reset() {
	r.RequestContext.Reset()

	r.bodySource.req = nil
	r.req = nil
}
