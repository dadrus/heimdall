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
		// copying explicitly, as it will be removed by the removeHopByHopHeaders
		// and if not copied, will be invalid
		upgradeT := string(upgradeType(&c.Request().Header))

		removeHopByHopHeaders(&c.Request().Header)

		if len(upgradeT) != 0 {
			c.Request().Header.Set("Connection", "Upgrade")
			c.Request().Header.Set("Upgrade", upgradeT)
		}

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

		return c.Next()
	}
}
