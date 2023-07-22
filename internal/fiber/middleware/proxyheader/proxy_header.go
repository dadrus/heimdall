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

package proxyheader

import (
	"fmt"
	"net/textproto"
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

const (
	headerForwarded     = "Forwarded"
	headerXForwardedFor = "X-Forwarded-For"
)

func New() fiber.Handler {
	return func(c *fiber.Ctx) error {
		stripHopByHopHeader(&c.Request().Header)

		// reuse already present headers only, if the source is trusted
		// otherwise delete these to avoid sending them to the upstream service
		// these headers shall not be set by the ultimate client
		forwardedForHeaderValue := c.Get(headerXForwardedFor)
		if !c.IsProxyTrusted() && len(forwardedForHeaderValue) != 0 {
			c.Request().Header.Del(headerXForwardedFor)

			forwardedForHeaderValue = ""
		}

		forwardedHeaderValue := c.Get(headerForwarded)
		if !c.IsProxyTrusted() && len(forwardedHeaderValue) != 0 {
			c.Request().Header.Del(headerForwarded)

			forwardedHeaderValue = ""
		}

		clientIP := c.IP()
		proto := stringx.ToString(c.Request().URI().Scheme())

		// Set the X-Forwarded-For
		c.Request().Header.Set(headerXForwardedFor,
			x.IfThenElseExec(len(forwardedForHeaderValue) == 0,
				func() string { return clientIP },
				func() string { return fmt.Sprintf("%s, %s", forwardedForHeaderValue, clientIP) }))

		// Set the Forwarded header
		c.Request().Header.Set(headerForwarded,
			x.IfThenElseExec(len(forwardedHeaderValue) == 0,
				func() string { return fmt.Sprintf("for=%s;proto=%s", clientIP, proto) },
				func() string { return fmt.Sprintf("%s, for=%s;proto=%s", forwardedHeaderValue, clientIP, proto) }))

		err := c.Next()

		removeHopByHopHeaders(&c.Response().Header)

		return err
	}
}

type headerAccessor interface {
	Peek(key string) []byte
	Set(key, value string)
	Del(key string)
}

func stripHopByHopHeader(header headerAccessor) {
	// copying explicitly, as it will be removed by the removeHopByHopHeaders
	// and if not copied, will be invalid
	upgradeT := string(upgradeType(header))

	removeHopByHopHeaders(header)

	if len(upgradeT) != 0 {
		header.Set("Connection", "upgrade")
		header.Set("Upgrade", upgradeT)
	}
}

func upgradeType(header headerAccessor) []byte {
	values := header.Peek("Connection")
	if strings.Contains(strings.ToLower(stringx.ToString(values)), "upgrade") {
		return header.Peek("Upgrade")
	}

	return nil
}

func removeHopByHopHeaders(header headerAccessor) {
	values := stringx.ToString(header.Peek("Connection"))

	// RFC 7230, section 6.1: Remove headers listed in the "Connection" header.
	for _, key := range strings.Split(values, ",") {
		if key = textproto.TrimString(key); key != "" {
			header.Del(key)
		}
	}

	// RFC 2616, section 13.5.1: Remove a set of known hop-by-hop headers.
	// This behavior is superseded by the RFC 7230 Connection header, but
	// preserve it for backwards compatibility.
	for _, f := range hopHeaders {
		header.Del(f)
	}
}

