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

	"github.com/gofiber/fiber/v2"

	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

func requestURL(c *fiber.Ctx) *url.URL {
	var (
		proto   string
		rawPath string
		path    string
		query   string
	)

	if c.IsProxyTrusted() {
		forwardedURIVal := c.Get(xForwardedURI)
		if len(forwardedURIVal) != 0 {
			forwardedURI, _ := url.Parse(forwardedURIVal)
			rawPath = forwardedURI.Path
			query = forwardedURI.Query().Encode()
		} else {
			rawPath = c.Get(xForwardedPath)
		}

		proto = c.Get(xForwardedProto)
	}

	if len(proto) == 0 {
		proto = x.IfThenElse(c.Context().IsTLS(), "https", "http")
	}

	if len(rawPath) == 0 {
		rawPath = c.Params("*")
		if len(rawPath) != 0 {
			rawPath = fmt.Sprintf("/%s", rawPath)
		}
	}

	if len(query) == 0 {
		origReqURL := *c.Request().URI()
		query = stringx.ToString(origReqURL.QueryString())
	}

	path, _ = url.PathUnescape(rawPath)

	return &url.URL{
		Scheme:   proto,
		Host:     c.Hostname(),
		Path:     path,
		RawQuery: query,
	}
}
