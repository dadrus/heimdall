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

package template

import (
	"net/url"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
)

type data struct {
	Request *Request
	Subject *subject.Subject
}

type Request struct {
	ctx heimdall.Context

	Method   string
	URL      *url.URL
	ClientIP []string
}

func (r *Request) Header(name string) string { return r.ctx.RequestHeader(name) }
func (r *Request) Cookie(name string) string { return r.ctx.RequestCookie(name) }

func WrapRequest(ctx heimdall.Context) *Request {
	return &Request{
		ctx:      ctx,
		Method:   ctx.RequestMethod(),
		URL:      ctx.RequestURL(),
		ClientIP: ctx.RequestClientIPs(),
	}
}
