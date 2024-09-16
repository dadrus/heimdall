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

func defaultOptions() *opts {
	defaults := &opts{}
	defaults.onAuthenticationError = errorWriter(defaults, http.StatusUnauthorized)
	defaults.onAuthorizationError = errorWriter(defaults, http.StatusForbidden)
	defaults.onCommunicationError = errorWriter(defaults, http.StatusBadGateway)
	defaults.onPreconditionError = errorWriter(defaults, http.StatusBadRequest)
	defaults.onNoRuleError = errorWriter(defaults, http.StatusNotFound)
	defaults.onInternalError = errorWriter(defaults, http.StatusInternalServerError)

	return defaults
}
