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

package errorhandler

import (
	"net/http"
)

var defaultOptions = opts{ //nolint:gochecknoglobals
	onAuthenticationError: func(rw http.ResponseWriter, req *http.Request, err error) {
		rw.WriteHeader(http.StatusUnauthorized)
	},
	onAuthorizationError: func(rw http.ResponseWriter, req *http.Request, err error) {
		rw.WriteHeader(http.StatusForbidden)
	},
	onCommunicationError: func(rw http.ResponseWriter, req *http.Request, err error) {
		rw.WriteHeader(http.StatusBadGateway)
	},
	onPreconditionError: func(rw http.ResponseWriter, req *http.Request, err error) {
		rw.WriteHeader(http.StatusBadRequest)
	},
	onBadMethodError: func(rw http.ResponseWriter, req *http.Request, err error) {
		rw.WriteHeader(http.StatusMethodNotAllowed)
	},
	onNoRuleError: func(rw http.ResponseWriter, req *http.Request, err error) {
		rw.WriteHeader(http.StatusNotFound)
	},
	onInternalError: func(rw http.ResponseWriter, req *http.Request, err error) {
		rw.WriteHeader(http.StatusInternalServerError)
	},
}
