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

//go:generate mockery --name RequestContext --structname RequestContextMock

type RequestContext interface {
	Request() *Request

	AddHeaderForUpstream(name, value string)
	AddCookieForUpstream(name, value string)

	Context() context.Context

	SetPipelineError(err error)

	Outputs() map[string]any
}

//go:generate mockery --name RequestFunctions --structname RequestFunctionsMock

type RequestFunctions interface {
	Header(name string) string
	Cookie(name string) string
	Headers() map[string]string
	Body() any
}

type URL struct {
	url.URL

	Captures map[string]string
}

type Request struct {
	RequestFunctions

	Method            string
	URL               *URL
	ClientIPAddresses []string
}
