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

package authstrategy

import "strings"

type TokenSuccessfulResponse struct {
	AccessToken string `json:"access_token,omitempty"`
	TokenType   string `json:"token_type,omitempty"`
	ExpiresIn   int64  `json:"expires_in,omitempty"`
	Scope       string `json:"scope,omitempty"`
}

type TokenErrorResponse struct { //nolint:errname
	ErrorType        string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}

func (e *TokenErrorResponse) Error() string {
	builder := strings.Builder{}
	builder.WriteString("error from oauth2 server: ")
	builder.WriteString("error: ")
	builder.WriteString(e.ErrorType)

	if len(e.ErrorDescription) != 0 {
		builder.WriteString(", error_description: ")
		builder.WriteString(e.ErrorDescription)
	}

	if len(e.ErrorURI) != 0 {
		builder.WriteString(", error_uri: ")
		builder.WriteString(e.ErrorURI)
	}

	return builder.String()
}

type TokenEndpointResponse struct {
	*TokenSuccessfulResponse
	*TokenErrorResponse
}

func (r TokenEndpointResponse) Error() error {
	// weird go behavior
	if r.TokenErrorResponse != nil {
		return r.TokenErrorResponse
	}

	return nil
}
