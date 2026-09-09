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

package httpx

import (
	"net/http"
	"strings"
)

const (
	grpcContentType   = "application/grpc"
	ndjsonContentType = "application/x-ndjson"
)

func ShouldDumpRequestBody(req *http.Request) bool {
	return req != nil &&
		req.ContentLength > 0 &&
		len(req.Header.Get("Upgrade")) == 0 &&
		!IsStreamingContentType(req.Header.Get("Content-Type"))
}

func ShouldDumpResponseBody(resp *http.Response) bool {
	return resp != nil &&
		resp.ContentLength > 0 &&
		resp.StatusCode != http.StatusSwitchingProtocols &&
		!IsStreamingContentType(resp.Header.Get("Content-Type"))
}

func IsStreamingContentType(contentType string) bool {
	contentType, _, _ = strings.Cut(strings.TrimSpace(contentType), ";")
	contentType = strings.ToLower(strings.TrimSpace(contentType))

	if strings.Contains(contentType, "stream") || contentType == ndjsonContentType {
		return true
	}

	if contentType == grpcContentType {
		return true
	}

	return len(contentType) > len(grpcContentType)+1 &&
		contentType[len(grpcContentType)] == '+' &&
		contentType[:len(grpcContentType)] == grpcContentType
}
