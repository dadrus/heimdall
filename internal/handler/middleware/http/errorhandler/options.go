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
	"net/http"
)

type opts struct {
	verboseErrors         bool
	onAuthenticationError func(rw http.ResponseWriter, req *http.Request, err error)
	onAuthorizationError  func(rw http.ResponseWriter, req *http.Request, err error)
	onCommunicationError  func(rw http.ResponseWriter, req *http.Request, err error)
	onPreconditionError   func(rw http.ResponseWriter, req *http.Request, err error)
	onNoRuleError         func(rw http.ResponseWriter, req *http.Request, err error)
	onInternalError       func(rw http.ResponseWriter, req *http.Request, err error)
}

type Option func(*opts)

func WithPreconditionErrorCode(code int) Option {
	return func(o *opts) {
		if code != 0 {
			o.onPreconditionError = errorWriter(o, code)
		}
	}
}

func WithAuthenticationErrorCode(code int) Option {
	return func(o *opts) {
		if code != 0 {
			o.onAuthenticationError = errorWriter(o, code)
		}
	}
}

func WithAuthorizationErrorCode(code int) Option {
	return func(o *opts) {
		if code != 0 {
			o.onAuthorizationError = errorWriter(o, code)
		}
	}
}

func WithCommunicationErrorCode(code int) Option {
	return func(o *opts) {
		if code != 0 {
			o.onCommunicationError = errorWriter(o, code)
		}
	}
}

func WithInternalServerErrorCode(code int) Option {
	return func(o *opts) {
		if code != 0 {
			o.onInternalError = errorWriter(o, code)
		}
	}
}

func WithNoRuleErrorCode(code int) Option {
	return func(o *opts) {
		if code != 0 {
			o.onNoRuleError = errorWriter(o, code)
		}
	}
}

func WithVerboseErrors(flag bool) Option {
	return func(o *opts) {
		o.verboseErrors = flag
	}
}
