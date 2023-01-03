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
	"context"
	"net/url"

	"github.com/gofiber/fiber/v2"

	"github.com/dadrus/heimdall/internal/x"
)

type (
	methodKey     struct{}
	requestURLKey struct{}
)

func New() fiber.Handler {
	return func(c *fiber.Ctx) error {
		method := requestMethod(c)
		reqURL := requestURL(c)

		ctx := context.WithValue(c.UserContext(), methodKey{}, method)
		ctx = context.WithValue(ctx, requestURLKey{}, reqURL)

		c.SetUserContext(ctx)

		return c.Next()
	}
}

// RequestMethod returns the HTTP method associated with the ctx. If no method is associated,
// an empty string is returned.
func RequestMethod(ctx context.Context) string {
	var (
		method string
		ok     bool
	)

	if val := ctx.Value(methodKey{}); val != nil {
		method, ok = val.(string)
	}

	return x.IfThenElse(ok, method, "")
}

// RequestURL returns the URL associated with the ctx. If no URL is associated,
// nil is returned.
func RequestURL(ctx context.Context) *url.URL {
	var (
		reqURL *url.URL
		ok     bool
	)

	if val := ctx.Value(requestURLKey{}); val != nil {
		reqURL, ok = val.(*url.URL)
	}

	return x.IfThenElse(ok, reqURL, nil)
}
