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

package requestcontext

import (
	"net/http"
	"net/url"

	"github.com/dadrus/heimdall/internal/x"
)

func extractURL(req *http.Request) *url.URL {
	var (
		rawPath string
		path    string
		query   string
	)

	proto := req.Header.Get("X-Forwarded-Proto")
	if len(proto) == 0 {
		proto = x.IfThenElse(req.TLS == nil, "http", "https")
	}

	host := req.Header.Get("X-Forwarded-Host")
	if len(host) == 0 {
		host = req.Host
	}

	if val := req.Header.Get("X-Forwarded-Uri"); len(val) != 0 {
		if forwardedURI, err := url.Parse(val); err == nil {
			rawPath = forwardedURI.Path
			query = forwardedURI.Query().Encode()
		}
	} else {
		rawPath = req.Header.Get("X-Forwarded-Path")
	}

	if len(rawPath) == 0 {
		rawPath = req.URL.Path
	}

	if len(query) == 0 {
		query = req.URL.RawQuery
	}

	path, _ = url.PathUnescape(rawPath)

	return &url.URL{
		Scheme:   proto,
		Host:     host,
		Path:     path,
		RawQuery: query,
	}
}
