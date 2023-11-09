// Copyright 2023 Dimitrij Drus <dadrus@gmx.de>
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

package errorhandler

import (
	"encoding/xml"
	"fmt"

	"github.com/elnormous/contenttype"
	envoy_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/goccy/go-json"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"

	"github.com/dadrus/heimdall/internal/x/stringx"
)

func responseWith(
	grpcCode codes.Code, httpCodeOverride int,
) func(err error, verbose bool, mimeType string) (any, error) {
	return func(err error, verbose bool, mimeType string) (any, error) {
		return errorResponse(grpcCode, httpCodeOverride, err, verbose, mimeType), nil
	}
}

func errorResponse(
	grpcCode codes.Code, httpCodeOverride int, decErr error, verbose bool, mimeType string,
) *envoy_auth.CheckResponse {
	deniedResponse := &envoy_auth.DeniedHttpResponse{
		Status: &envoy_type.HttpStatus{Code: envoy_type.StatusCode(httpCodeOverride)},
	}

	if verbose {
		contentType := "text/html"

		mt, _, err := contenttype.GetAcceptableMediaTypeFromHeader(
			mimeType, []contenttype.MediaType{
				{Type: "application", Subtype: "json"},
				{Type: "application", Subtype: "xml"},
				{Type: "text", Subtype: "html"},
				{Type: "text", Subtype: "plain"},
			})
		if err == nil {
			contentType = mt.MIME()
		}

		body, _ := format(contentType, decErr)

		deniedResponse.Headers = []*envoy_core.HeaderValueOption{
			{Header: &envoy_core.HeaderValue{Key: "Content-Type", Value: contentType}},
		}
		deniedResponse.Body = body
	}

	return &envoy_auth.CheckResponse{
		Status:       &status.Status{Code: int32(grpcCode)},
		HttpResponse: &envoy_auth.CheckResponse_DeniedResponse{DeniedResponse: deniedResponse},
	}
}

func format(mimeType string, body any) (string, error) {
	switch mimeType {
	case "text/html":
		return fmt.Sprintf("<p>%s</p>", body), nil
	case "application/json":
		res, err := json.Marshal(body)

		return stringx.ToString(res), err
	case "application/xml":
		res, err := xml.Marshal(body)

		return stringx.ToString(res), err
	case "test/plain":
		fallthrough
	default:
		return fmt.Sprintf("%s", body), nil
	}
}
