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

import "google.golang.org/grpc/codes"

type opts struct {
	verboseErrors       bool
	authenticationError func(err error, verbose bool, mimeType string) (any, error)
	authorizationError  func(err error, verbose bool, mimeType string) (any, error)
	communicationError  func(err error, verbose bool, mimeType string) (any, error)
	preconditionError   func(err error, verbose bool, mimeType string) (any, error)
	badMethodError      func(err error, verbose bool, mimeType string) (any, error)
	noRuleError         func(err error, verbose bool, mimeType string) (any, error)
	internalError       func(err error, verbose bool, mimeType string) (any, error)
}

type Option func(*opts)

func WithPreconditionErrorCode(code int) Option {
	return func(o *opts) {
		if code > 0 {
			o.preconditionError = responseWith(codes.InvalidArgument, code)
		}
	}
}

func WithAuthenticationErrorCode(code int) Option {
	return func(o *opts) {
		if code > 0 {
			o.authenticationError = responseWith(codes.Unauthenticated, code)
		}
	}
}

func WithAuthorizationErrorCode(code int) Option {
	return func(o *opts) {
		if code > 0 {
			o.authorizationError = responseWith(codes.PermissionDenied, code)
		}
	}
}

func WithCommunicationErrorCode(code int) Option {
	return func(o *opts) {
		if code > 0 {
			o.communicationError = responseWith(codes.DeadlineExceeded, code)
		}
	}
}

func WithInternalServerErrorCode(code int) Option {
	return func(o *opts) {
		if code > 0 {
			o.internalError = responseWith(codes.Internal, code)
		}
	}
}

func WithMethodErrorCode(code int) Option {
	return func(o *opts) {
		if code > 0 {
			o.badMethodError = responseWith(codes.InvalidArgument, code)
		}
	}
}

func WithNoRuleErrorCode(code int) Option {
	return func(o *opts) {
		if code > 0 {
			o.noRuleError = responseWith(codes.NotFound, code)
		}
	}
}

func WithVerboseErrors(flag bool) Option {
	return func(o *opts) {
		o.verboseErrors = flag
	}
}
