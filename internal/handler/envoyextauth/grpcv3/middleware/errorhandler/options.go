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
    "fmt"

    envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
    envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
    "google.golang.org/genproto/googleapis/rpc/status"
)

type opts struct {
    verboseErrors       bool
    authenticationError func(err error, verbose bool) (any, error)
    authorizationError  func(err error, verbose bool) (any, error)
    communicationError  func(err error, verbose bool) (any, error)
    preconditionError   func(err error, verbose bool) (any, error)
    badMethodError      func(err error, verbose bool) (any, error)
    noRuleError         func(err error, verbose bool) (any, error)
    internalError       func(err error, verbose bool) (any, error)
}

type Option func(*opts)

func WithPreconditionErrorCode(code int) Option {
    return func(o *opts) {
        if code != 0 {
            o.preconditionError = func(err error, verbose bool) (any, error) {
                return createDeniedResponse(code, err, verbose), nil
            }
        }
    }
}

func WithAuthenticationErrorCode(code int) Option {
    return func(o *opts) {
        if code != 0 {
            o.authenticationError = func(err error, verbose bool) (any, error) {
                return createDeniedResponse(code, err, verbose), nil
            }
        }
    }
}

func WithAuthorizationErrorCode(code int) Option {
    return func(o *opts) {
        if code != 0 {
            o.authorizationError = func(err error, verbose bool) (any, error) {
                return createDeniedResponse(code, err, verbose), nil
            }
        }
    }
}

func WithCommunicationErrorCode(code int) Option {
    return func(o *opts) {
        if code != 0 {
            o.communicationError = func(err error, verbose bool) (any, error) {
                return createDeniedResponse(code, err, verbose), nil
            }
        }
    }
}

func WithInternalServerErrorCode(code int) Option {
    return func(o *opts) {
        if code != 0 {
            o.internalError = func(err error, verbose bool) (any, error) {
                return createDeniedResponse(code, err, verbose), nil
            }
        }
    }
}

func WithMethodErrorCode(code int) Option {
    return func(o *opts) {
        if code != 0 {
            o.badMethodError = func(err error, verbose bool) (any, error) {
                return createDeniedResponse(code, err, verbose), nil
            }
        }
    }
}

func WithNoRuleErrorCode(code int) Option {
    return func(o *opts) {
        if code != 0 {
            o.noRuleError = func(err error, verbose bool) (any, error) {
                return createDeniedResponse(code, err, verbose), nil
            }
        }
    }
}

func WithVerboseErrors(flag bool) Option {
    return func(o *opts) {
        o.verboseErrors = flag
    }
}

func createDeniedResponse(code int, err error, verbose bool) *envoy_auth.CheckResponse {
    return &envoy_auth.CheckResponse{
        Status: &status.Status{Code: int32(code)},
        HttpResponse: &envoy_auth.CheckResponse_DeniedResponse{
            DeniedResponse: &envoy_auth.DeniedHttpResponse{
                Status: &envoy_type.HttpStatus{Code: envoy_type.StatusCode(code)},
                Body:   messageFrom(err, verbose),
            },
        },
    }
}

func messageFrom(err error, verbose bool) string {
    if !verbose {
        return ""
    }

    if se, ok := err.(fmt.Stringer); ok {
        return se.String()
    } else {
        return err.Error()
    }
}
