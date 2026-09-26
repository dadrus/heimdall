// Copyright 2026 Dimitrij Drus <dadrus@gmx.de>
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

package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func BenchmarkProxyInvocation(b *testing.B) {
	req := httptest.NewRequestWithContext(
		b.Context(),
		http.MethodGet,
		"https://foo.bar/test",
		nil,
	)
	rc := &requestContext{}

	var result *proxyInvocation

	b.ReportAllocs()

	for b.Loop() {
		invocation := proxyInvocation{
			request: rc,
		}

		ctx := context.WithValue(
			req.Context(),
			proxyInvocationKey{},
			&invocation,
		)

		proxyReq := req.WithContext(ctx)
		result = proxyInvocationFrom(proxyReq.Context())
	}

	if result == nil || result.request != rc {
		b.Fatal("unexpected proxy invocation")
	}
}
