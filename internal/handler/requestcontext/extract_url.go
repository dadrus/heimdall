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
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/urlx"
)

// ErrInvalidForwardedURI indicates that an explicitly supplied request target
// cannot be used as the resource for authorization.
var ErrInvalidForwardedURI = errors.New("invalid X-Forwarded-Uri")

func extractURL(req *http.Request) (url.URL, error) {
	proto := req.Header.Get("X-Forwarded-Proto")
	if len(proto) == 0 {
		proto = x.IfThenElse(req.TLS == nil, "http", "https")
	}

	host := req.Header.Get("X-Forwarded-Host")
	if len(host) == 0 {
		host = req.Host
	}

	host = strings.ToLower(host)

	source := req.URL
	forwarded := req.Header.Get("X-Forwarded-Uri")
	if len(forwarded) != 0 {
		forwardedURI, err := url.ParseRequestURI(forwarded)
		if err != nil {
			return url.URL{}, ErrInvalidForwardedURI
		}

		source = forwardedURI
	}

	rawPath := urlx.EscapedPath(source)
	if len(forwarded) != 0 && len(rawPath) == 0 {
		return url.URL{}, ErrInvalidForwardedURI
	}

	rawPath = urlx.NormalizePath(rawPath)
	path, _ := url.PathUnescape(rawPath)

	return url.URL{
		Scheme:     proto,
		Host:       host,
		Path:       path,
		RawPath:    rawPath,
		RawQuery:   source.RawQuery,
		ForceQuery: source.ForceQuery,
	}, nil
}
