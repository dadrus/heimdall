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

package validate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/cmd/flags"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/x/pkix/pemx"
)

func TestValidateConfig(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	pemBytes, err := pemx.BuildPEM(
		pemx.WithECDSAPrivateKey(privKey, pemx.WithHeader("X-Key-ID", "key")),
	)
	require.NoError(t, err)

	testDir := t.TempDir()
	pemFile := filepath.Join(testDir, "keystore.pem")

	err = os.WriteFile(pemFile, pemBytes, 0o600)
	require.NoError(t, err)

	t.Setenv("TEST_KEYSTORE_FILE", pemFile)

	for name, tc := range map[string]struct {
		args   []string
		expErr string
	}{
		"no config provided": {
			expErr: "no config",
		},
		"not existing config": {
			args:   []string{"--" + flags.Config, "doesnotexist.yaml"},
			expErr: "stat doesnotexist.yaml",
		},
		"insecure trusted proxies configured": {
			args:   []string{"--" + flags.Config, "test_data/config-insecure-trusted-proxies.yaml"},
			expErr: "'serve'.'trusted_proxies' contains insecure networks",
		},
		"no TLS configured for ingres services": {
			args:   []string{"--" + flags.Config, "test_data/config-no-tls-config-for-ingres-services.yaml"},
			expErr: "'serve'.'tls' must be configured",
		},
		"no https configured for generic authenticator": {
			args:   []string{"--" + flags.Config, "test_data/config-no-https-endpoint-in-generic-authenticator.yaml"},
			expErr: "'identity_info_endpoint'.'url' scheme must be https",
		},
		"no https configured for jwks_endpoint in jwt authenticator": {
			args:   []string{"--" + flags.Config, "test_data/config-no-https-jwks-endpoint-in-jwt-authenticator.yaml"},
			expErr: "'jwks_endpoint'.'url' scheme must be https",
		},
		"no https configured for metadata_endpoint in jwt authenticator": {
			args:   []string{"--" + flags.Config, "test_data/config-no-https-metadata-endpoint-in-jwt-authenticator.yaml"},
			expErr: "'metadata_endpoint'.'url' scheme must be https",
		},
		"no https configured for oath2 introspection authenticator endpoint": {
			args:   []string{"--" + flags.Config, "test_data/config-no-https-endpoint-in-oauth2-introspection-authenticator.yaml"},
			expErr: "'introspection_endpoint'.'url' scheme must be https",
		},
		"no https configured for remote authorizer endpoint": {
			args:   []string{"--" + flags.Config, "test_data/config-no-https-endpoint-in-remote-authorizer.yaml"},
			expErr: "'endpoint'.'url' scheme must be https",
		},
		"no https configured for oauth2 client credentials finalizer": {
			args:   []string{"--" + flags.Config, "test_data/config-no-https-endpoint-in-oauth2-client-credentials-finalizer.yaml"},
			expErr: "'token_url' scheme must be https",
		},
		"no https configured for generic contextualzer": {
			args:   []string{"--" + flags.Config, "test_data/config-no-https-endpoint-in-generic-contextualizer.yaml"},
			expErr: "'endpoint'.'url' scheme must be https",
		},
		"no https in oauth2 client credentials authentication strategy": {
			args:   []string{"--" + flags.Config, "test_data/config-no-https-in-oauth2-client-credentials-authentication-strategy.yaml"},
			expErr: "failed validating 'oauth2_client_credentials' strategy",
		},
		"no https in http endpoint rule provider": {
			args:   []string{"--" + flags.Config, "test_data/config-no-https-in-http-endpoint-provider.yaml"},
			expErr: "'endpoints'[0].'url' scheme must be https",
		},
		"tls is disabled for redis cache": {
			args:   []string{"--" + flags.Config, "test_data/config-no-tls-in-redis-cache.yaml"},
			expErr: "'tls'.'disabled' must be false",
		},
		"no default principal in default rule": {
			args:   []string{"--" + flags.Config, "test_data/config-no-default-principal-in-default-rule.yaml"},
			expErr: "no authenticator defined which would create a default principal",
		},
		"valid config with default rule": {
			args: []string{"--" + flags.Config, "test_data/config-valid-with-default-rule.yaml"},
		},
		"valid config without default rule": {
			args: []string{"--" + flags.Config, "test_data/config-valid-without-default-rule.yaml"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			// GIVEN
			cmd := NewValidateConfigCommand()
			flags.RegisterGlobalFlags(cmd)

			cmd.SetArgs(tc.args)

			// WHEN
			err = cmd.Execute()

			// THEN
			if len(tc.expErr) != 0 {
				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, tc.expErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
