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
	"context"
	"errors"

	envoy_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/rs/zerolog"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"github.com/dadrus/heimdall/internal/accesscontext"
	"github.com/dadrus/heimdall/internal/pipeline"
)

func New(opts ...Option) grpc.UnaryServerInterceptor {
	options := defaultOptions

	for _, opt := range opts {
		opt(&options)
	}

	h := &interceptor{opts: options}

	return h.intercept
}

type interceptor struct {
	opts
}

func hasCustomResponse(responseError *pipeline.ResponseError) bool {
	return responseError.Code != 0 ||
		len(responseError.Headers) != 0 ||
		len(responseError.Body) != 0
}

func (h *interceptor) intercept(
	ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
) (any, error) {
	res, err := handler(ctx, req)
	if err == nil {
		return res, nil
	}

	if resp, cause, handled := h.handleCustomError(ctx, err); handled {
		return resp, nil
	} else {
		err = cause
	}

	if resp, handled := h.handleRedirectError(ctx, err); handled {
		return resp, nil
	}

	return h.handleDefaultErrors(ctx, err, acceptType(req))
}

func (h *interceptor) handleCustomError(ctx context.Context, err error) (any, error, bool) {
	responseError, ok := errors.AsType[*pipeline.ResponseError](err)
	if !ok {
		return nil, err, false
	}

	if !hasCustomResponse(responseError) {
		return nil, responseError.Cause, false
	}

	accesscontext.SetError(ctx, responseError.Cause)

	return buildDeniedResponse(
		//nolint:gosec
		// no integer overflow during conversion possible
		envoy_type.StatusCode(responseError.Code),
		buildHeaderOptions(responseError.Headers),
		responseError.Body,
	), nil, true
}

func (h *interceptor) handleRedirectError(ctx context.Context, err error) (any, bool) {
	redirectError, ok := errors.AsType[*pipeline.RedirectError](err)
	if !ok {
		return nil, false
	}

	accesscontext.SetError(ctx, redirectError.Cause)

	return buildDeniedResponse(
		//nolint:gosec
		// no integer overflow during conversion possible
		envoy_type.StatusCode(redirectError.Code),
		[]*envoy_core.HeaderValueOption{
			{
				Header: &envoy_core.HeaderValue{
					Key:   "Location",
					Value: redirectError.RedirectTo,
				},
			},
		},
		"",
	), true
}

func (h *interceptor) handleDefaultErrors(ctx context.Context, err error, mimeType string) (any, error) {
	accesscontext.SetError(ctx, err)

	switch {
	case errors.Is(err, pipeline.ErrAuthentication):
		return h.authenticationError(err, h.verboseErrors, mimeType)
	case errors.Is(err, pipeline.ErrAuthorization):
		return h.authorizationError(err, h.verboseErrors, mimeType)
	case errors.Is(err, pipeline.ErrCommunicationTimeout) || errors.Is(err, pipeline.ErrCommunication):
		return h.communicationError(err, h.verboseErrors, mimeType)
	case errors.Is(err, pipeline.ErrArgument):
		return h.preconditionError(err, h.verboseErrors, mimeType)
	case errors.Is(err, pipeline.ErrNoRuleFound):
		return h.noRuleError(err, h.verboseErrors, mimeType)
	default:
		logger := zerolog.Ctx(ctx)
		logger.Error().Err(err).Msg("Internal error occurred")

		return h.internalError(err, h.verboseErrors, mimeType)
	}
}

func acceptType(req any) string {
	if req, ok := req.(*envoy_auth.CheckRequest); ok {
		return req.GetAttributes().GetRequest().GetHttp().GetHeaders()["accept"]
	}

	// This should never happen as the API is typed
	return ""
}

func buildDeniedResponse(
	statusCode envoy_type.StatusCode,
	headers []*envoy_core.HeaderValueOption,
	body string,
) *envoy_auth.CheckResponse {
	return &envoy_auth.CheckResponse{
		Status: &status.Status{Code: int32(codes.FailedPrecondition)},
		HttpResponse: &envoy_auth.CheckResponse_DeniedResponse{
			DeniedResponse: &envoy_auth.DeniedHttpResponse{
				Status:  &envoy_type.HttpStatus{Code: statusCode},
				Headers: headers,
				Body:    body,
			},
		},
	}
}

func buildHeaderOptions(headers map[string][]string) []*envoy_core.HeaderValueOption {
	result := make([]*envoy_core.HeaderValueOption, 0)

	for name, values := range headers {
		for _, value := range values {
			result = append(result, &envoy_core.HeaderValueOption{
				Header: &envoy_core.HeaderValue{
					Key:   name,
					Value: value,
				},
			})
		}
	}

	return result
}
