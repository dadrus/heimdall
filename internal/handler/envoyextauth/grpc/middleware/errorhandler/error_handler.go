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
    "github.com/rs/zerolog"
    "google.golang.org/genproto/googleapis/rpc/status"
    "google.golang.org/grpc"

    "github.com/dadrus/heimdall/internal/accesscontext"
    "github.com/dadrus/heimdall/internal/heimdall"
)

func New(opts ...Option) grpc.UnaryServerInterceptor {
    options := defaultOptions

    for _, opt := range opts {
        opt(&options)
    }

    h := &handler{opts: options}

    return h.handle
}

type handler struct {
    opts
}

func (h *handler) handle(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) { //nolint:cyclop
    res, err := handler(ctx, req)
    if err == nil {
        return res, nil
    }

    accesscontext.SetError(ctx, err)

    switch {
    case errors.Is(err, heimdall.ErrAuthentication):
        err = h.authenticationError(err, h.verboseErrors)
    case errors.Is(err, heimdall.ErrAuthorization):
        err = h.authorizationError(err, h.verboseErrors)
    case errors.Is(err, heimdall.ErrCommunicationTimeout) || errors.Is(err, heimdall.ErrCommunication):
        err = h.communicationError(err, h.verboseErrors)
    case errors.Is(err, heimdall.ErrArgument):
        err = h.preconditionError(err, h.verboseErrors)
    case errors.Is(err, heimdall.ErrMethodNotAllowed):
        err = h.badMethodError(err, h.verboseErrors)
    case errors.Is(err, heimdall.ErrNoRuleFound):
        err = h.noRuleError(err, h.verboseErrors)
    case errors.Is(err, &heimdall.RedirectError{}):
        var redirectError *heimdall.RedirectError

        errors.As(err, &redirectError)

        return &envoy_auth.CheckResponse{
            Status: &status.Status{Code: int32(redirectError.Code)},
            HttpResponse: &envoy_auth.CheckResponse_OkResponse{
                OkResponse: &envoy_auth.OkHttpResponse{Headers: []*envoy_core.HeaderValueOption{
                    {
                        Header: &envoy_core.HeaderValue{
                            Key:   "Location",
                            Value: redirectError.RedirectTo,
                        },
                    },
                }},
            },
        }, nil

    default:
        logger := zerolog.Ctx(ctx)
        logger.Error().Err(err).Msg("Internal error occurred")

        err = h.internalError(err, h.verboseErrors)
    }

    return req, err
}
