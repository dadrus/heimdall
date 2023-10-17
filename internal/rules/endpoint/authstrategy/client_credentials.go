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

import (
	"context"
	"net/http"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/rules/oauth2/clientcredentials"
)

type HeaderConfig struct {
	Name   string `mapstructure:"name"   validate:"required"`
	Scheme string `mapstructure:"scheme"`
}

type OAuth2ClientCredentials struct {
	clientcredentials.Config `mapstructure:",squash"`

	Header *HeaderConfig `mapstructure:"header"`
}

func (c *OAuth2ClientCredentials) Apply(ctx context.Context, req *http.Request) error {
	logger := zerolog.Ctx(ctx)
	logger.Debug().Msg("Applying oauth2_client_credentials strategy to authenticate request")

	token, err := c.Token(ctx)
	if err != nil {
		return err
	}

	headerName := "Authorization"
	if c.Header != nil {
		headerName = c.Header.Name
	}

	headerScheme := token.TokenType
	if c.Header != nil && len(c.Header.Scheme) != 0 {
		headerScheme = c.Header.Scheme
	}

	req.Header.Set(headerName, headerScheme+" "+token.AccessToken)

	return nil
}
