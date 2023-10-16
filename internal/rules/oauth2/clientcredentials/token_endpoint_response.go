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

package clientcredentials

import (
	"strings"
	"time"
)

type TokenInfo struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	Expiry       time.Time
	Scopes       []string

	raw map[string]any
}

func (t *TokenInfo) WithExtra(extra map[string]any) *TokenInfo {
	t2 := new(TokenInfo)
	*t2 = *t
	t2.raw = extra

	return t2
}

func (t *TokenInfo) Extra(key string) any { return t.raw[key] }

type TokenInfoResponse struct {
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

func (t *TokenInfoResponse) Type() string {
	switch {
	case strings.EqualFold(t.TokenType, "bearer"):
		return "Bearer"
	case strings.EqualFold(t.TokenType, "mac"):
		return "MAC"
	case strings.EqualFold(t.TokenType, "basic"):
		return "Basic"
	case t.TokenType != "":
		return t.TokenType
	default:
		return "Bearer"
	}
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
	*TokenInfoResponse
	*TokenErrorResponse
}

func (r TokenEndpointResponse) error() error {
	// weird go behavior
	if r.TokenErrorResponse != nil {
		return r.TokenErrorResponse
	}

	return nil
}

func (r TokenEndpointResponse) TokenInfo() (*TokenInfo, error) {
	if err := r.error(); err != nil {
		return nil, err
	}

	var expiry time.Time
	if r.ExpiresIn != 0 {
		expiry = time.Now().Add(time.Duration(r.ExpiresIn) * time.Second)
	}

	return &TokenInfo{
		AccessToken:  r.AccessToken,
		RefreshToken: r.RefreshToken,
		TokenType:    r.Type(),
		Expiry:       expiry,
		Scopes:       strings.Split(r.Scope, " "),
	}, nil
}
