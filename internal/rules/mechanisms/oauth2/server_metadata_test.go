// Copyright 2022-2025 Dimitrij Drus <dadrus@gmx.de>
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

package oauth2

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
)

func TestServerMetadataVerifyIssuer(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		metadataURL string
		issuer      string
		matching    bool
	}{
		{
			metadataURL: "https://example.com/issuer1/.well-known/openid-configuration",
			issuer:      "https://example.com/issuer1",
			matching:    true,
		},
		{
			metadataURL: "https://example.com/issuer1/.well-known/openid-configuration",
			issuer:      "https://example.com/issuer1/",
			matching:    true,
		},
		{
			metadataURL: "https://example.com/realms/issuer1/.well-known/openid-configuration",
			issuer:      "https://example.com/realms/issuer1",
			matching:    true,
		},
		{
			metadataURL: "https://example.com/realms/issuer1/.well-known/openid-configuration",
			issuer:      "https://example.com/realms/issuer1/",
			matching:    true,
		},
		{
			metadataURL: "https://example.com/.well-known/openid-configuration",
			issuer:      "https://example.com",
			matching:    true,
		},
		{
			metadataURL: "https://example.com/.well-known/openid-configuration",
			issuer:      "https://example.com/",
			matching:    true,
		},
		{
			metadataURL: "https://example.com/.well-known/openid-configuration/issuer1",
			issuer:      "https://example.com/issuer1",
			matching:    true,
		},
		{
			metadataURL: "https://example.com/.well-known/openid-configuration/issuer1",
			issuer:      "https://example.com/issuer1/",
			matching:    true,
		},
		{
			metadataURL: "https://example.com/.well-known/oauth-authorization-server/issuer1",
			issuer:      "https://example.com/issuer1",
			matching:    true,
		},
		{
			metadataURL: "https://example.com/.well-known/oauth-authorization-server/issuer1",
			issuer:      "https://example.com/issuer1/",
			matching:    true,
		},
		{
			metadataURL: "https://example.com/.well-known/oauth-authorization-server",
			issuer:      "https://example.com",
			matching:    true,
		},
		{
			metadataURL: "https://example.com/.well-known/oauth-authorization-server",
			issuer:      "https://example.com/",
			matching:    true,
		},
		{
			metadataURL: "https://example.com/.well-known/example-configuration",
			issuer:      "https://example.com",
			matching:    true,
		},
		{
			metadataURL: "https://example.com/.well-known/example-configuration",
			issuer:      "https://example.com/",
			matching:    true,
		},
		{
			metadataURL: "https://example.com/.well-known/example-configuration/",
			issuer:      "https://example.com",
			matching:    true,
		},
		{
			metadataURL: "https://example.com/.well-known/example-configuration/",
			issuer:      "https://example.com/",
			matching:    true,
		},
		{
			metadataURL: "https://example.com/.well-known/example-configuration/issuer1",
			issuer:      "https://example.com/issuer1",
			matching:    true,
		},
		{
			metadataURL: "https://example.com/.well-known/example-configuration/issuer1",
			issuer:      "https://example.com/issuer1/",
			matching:    true,
		},
		{
			metadataURL: "https://example.com/.well-known/example-configuration/issuer1/",
			issuer:      "https://example.com/issuer1",
			matching:    true,
		},
		{
			metadataURL: "https://example.com/.well-known/example-configuration/issuer1/",
			issuer:      "https://example.com/issuer1/",
			matching:    true,
		},
		{
			metadataURL: "https://example.com/example-configuration/issuer1/",
			issuer:      "https://example.com/example-configuration/issuer1",
			matching:    true,
		},
		{
			metadataURL: "https://example.com/example-configuration/issuer1/",
			issuer:      "https://example.com/example-configuration/issuer1/",
			matching:    true,
		},
		{
			metadataURL: "https://example.com/example-configuration/issuer1",
			issuer:      "https://example.com",
			matching:    false,
		},
	} {
		t.Run(tc.metadataURL, func(t *testing.T) {
			// GIVEN
			sm := ServerMetadata{Issuer: tc.issuer}

			// WHEN
			err := sm.verify(tc.metadataURL)

			// THEN
			if tc.matching {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
			}
		})
	}
}
