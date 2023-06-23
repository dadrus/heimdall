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
	"github.com/gofiber/fiber/v2"
)

func requestMethod(c *fiber.Ctx) string {
	if c.IsProxyTrusted() {
		forwardedMethodVal := c.Get(xForwardedMethod)
		if len(forwardedMethodVal) != 0 {
			return forwardedMethodVal
		}

		// used by nginx ingress controller
		forwardedMethodVal = c.Get(xOriginalMethod)
		if len(forwardedMethodVal) != 0 {
			return forwardedMethodVal
		}
	}

	return c.Method()
}
