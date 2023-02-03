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
		if code != 0 {
			o.preconditionError = func(err error, verbose bool, mimeType string) (any, error) {
				return errorResponse(code, err, verbose, mimeType), nil
			}
		}
	}
}

func WithAuthenticationErrorCode(code int) Option {
	return func(o *opts) {
		if code != 0 {
			o.authenticationError = func(err error, verbose bool, mimeType string) (any, error) {
				return errorResponse(code, err, verbose, mimeType), nil
			}
		}
	}
}

func WithAuthorizationErrorCode(code int) Option {
	return func(o *opts) {
		if code != 0 {
			o.authorizationError = func(err error, verbose bool, mimeType string) (any, error) {
				return errorResponse(code, err, verbose, mimeType), nil
			}
		}
	}
}

func WithCommunicationErrorCode(code int) Option {
	return func(o *opts) {
		if code != 0 {
			o.communicationError = func(err error, verbose bool, mimeType string) (any, error) {
				return errorResponse(code, err, verbose, mimeType), nil
			}
		}
	}
}

func WithInternalServerErrorCode(code int) Option {
	return func(o *opts) {
		if code != 0 {
			o.internalError = func(err error, verbose bool, mimeType string) (any, error) {
				return errorResponse(code, err, verbose, mimeType), nil
			}
		}
	}
}

func WithMethodErrorCode(code int) Option {
	return func(o *opts) {
		if code != 0 {
			o.badMethodError = func(err error, verbose bool, mimeType string) (any, error) {
				return errorResponse(code, err, verbose, mimeType), nil
			}
		}
	}
}

func WithNoRuleErrorCode(code int) Option {
	return func(o *opts) {
		if code != 0 {
			o.noRuleError = func(err error, verbose bool, mimeType string) (any, error) {
				return errorResponse(code, err, verbose, mimeType), nil
			}
		}
	}
}

func WithVerboseErrors(flag bool) Option {
	return func(o *opts) {
		o.verboseErrors = flag
	}
}
