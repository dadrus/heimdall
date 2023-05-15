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

package heimdall

import (
	"context"
	"net/url"
)

//go:generate mockery --name Context --structname ContextMock

type Context interface { // nolint: interfacebloat
	Request() *Request
	RequestMethod() string
	RequestHeaders() map[string]string
	RequestHeader(key string) string
	RequestCookie(key string) string
	RequestQueryParameter(key string) string
	RequestFormParameter(key string) string
	RequestBody() []byte
	RequestURL() *url.URL
	RequestClientIPs() []string

	AddHeaderForUpstream(name, value string)
	AddCookieForUpstream(name, value string)

	AppContext() context.Context

	SetPipelineError(err error)

	Signer() JWTSigner
}

//go:generate mockery --name RequestFunctions --structname RequestFunctionsMock

type RequestFunctions interface {
	Header(name string) string
	Cookie(name string) string
}

type Request struct {
	RequestFunctions

	Method   string
	URL      *url.URL
	ClientIP []string
}
