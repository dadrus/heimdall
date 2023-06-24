// Copyright 2022 Dimitrij Drus <dadrus@gmx.de>
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

package xfmphu

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

func requestURL(c *fiber.Ctx) *url.URL {
	var (
		proto   string
		host    string
		rawPath string
		path    string
		query   string
	)

	if c.IsProxyTrusted() {
		forwardedURIVal := c.Get(xForwardedURI)
		if len(forwardedURIVal) != 0 {
			forwardedURI, _ := url.Parse(forwardedURIVal)
			proto = forwardedURI.Scheme
			host = forwardedURI.Host
			rawPath = forwardedURI.Path
			query = forwardedURI.Query().Encode()
		}
	}

	if len(rawPath) == 0 && c.IsProxyTrusted() {
		rawPath = c.Get(xForwardedPath)
	}

	if len(rawPath) == 0 {
		rawPath = c.Params("*")
		if len(rawPath) != 0 {
			rawPath = fmt.Sprintf("/%s", rawPath)
		}

		// there is a bug in the implementation of the nginx controller
		// see: https://github.com/kubernetes/ingress-nginx/issues/10114
		if c.Get(xSentFrom) == nginxIngressAgent && strings.HasPrefix(rawPath, "//") {
			rawPath = strings.TrimPrefix(rawPath, "/")
		}
	}

	if len(query) == 0 {
		origReqURL := *c.Request().URI()
		query = stringx.ToString(origReqURL.QueryString())
	}

	path, _ = url.PathUnescape(rawPath)

	return &url.URL{
		Scheme: x.IfThenElseExec(len(proto) != 0,
			func() string { return proto },
			func() string { return c.Protocol() }),
		Host: x.IfThenElseExec(len(host) != 0,
			func() string { return host },
			func() string { return c.Hostname() }),
		Path:     path,
		RawQuery: query,
	}
}
