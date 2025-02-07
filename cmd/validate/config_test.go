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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/cmd/flags"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/pkix/pemx"
	"github.com/dadrus/heimdall/internal/x/testsupport"
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
		confFile string
		assert   func(t *testing.T, err error)
	}{
		"no config provided": {
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "no config")
			},
		},
		"not existing config": {
			confFile: "doesnotexist.yaml",
			assert: func(t *testing.T, err error) {
				t.Helper()
				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorIs(t, err, os.ErrNotExist)
			},
		},
		"insecure trusted proxies configured": {
			confFile: "test_data/config-insecure-trusted-proxies.yaml",
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "'serve'.'trusted_proxies' contains insecure networks")
			},
		},
		"no TLS configured for ingres services": {
			confFile: "test_data/config-no-tls-config-for-ingres-services.yaml",
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "'serve'.'tls' must be configured")
				require.ErrorContains(t, err, "'management'.'tls' must be configured")
			},
		},
		"no https configured for generic authenticator": {
			confFile: "test_data/config-no-https-endpoint-in-generic-authenticator.yaml",
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "'identity_info_endpoint'.'url' scheme must be https")
			},
		},
		"no https configured for jwks_endpoint in jwt authenticator": {
			confFile: "test_data/config-no-https-jwks-endpoint-in-jwt-authenticator.yaml",
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "'jwks_endpoint'.'url' scheme must be https")
			},
		},
		"no https configured for metadata_endpoint in jwt authenticator": {
			confFile: "test_data/config-no-https-metadata-endpoint-in-jwt-authenticator.yaml",
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "'metadata_endpoint'.'url' scheme must be https")
			},
		},
		"no https configured for oath2 introspection authenticator enpoint": {
			confFile: "test_data/config-no-https-endpoint-in-oauth2-introspection-authenticator.yaml",
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "'introspection_endpoint'.'url' scheme must be https")
			},
		},
		"no https configured for remote authorizer endpoint": {
			confFile: "test_data/config-no-https-endpoint-in-remote-authorizer.yaml",
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "'endpoint'.'url' scheme must be https")
			},
		},
		"no https configured for oauth2 client credentials finalizer": {
			confFile: "test_data/config-no-https-endpoint-in-oauth2-client-credentials-finalizer.yaml",
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "'token_url' scheme must be https")
			},
		},
		"no https configured for generic contextualzer": {
			confFile: "test_data/config-no-https-endpoint-in-generic-contextualizer.yaml",
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "'endpoint'.'url' scheme must be https")
			},
		},
		"no https in oauth2 client credentials authentication strategy": {
			confFile: "test_data/config-no-https-in-oauth2-client-credentials-authentication-strategy.yaml",
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "failed validating 'oauth2_client_credentials' strategy")
				require.ErrorContains(t, err, "'token_url' scheme must be https")
			},
		},
		"no https in http endpoint rule provider": {
			confFile: "test_data/config-no-https-in-http-endpoint-provider.yaml",
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "'endpoints'[0].'url' scheme must be https")
			},
		},
		"tls is disabled for redis cache": {
			confFile: "test_data/config-no-tls-in-redis-cache.yaml",
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "failed validating redis")
				require.ErrorContains(t, err, "'tls'.'disabled' must be false")
			},
		},
		"valid config": {
			confFile: "test_data/config-valid.yaml",
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			// GIVEN
			cmd := NewValidateConfigCommand()
			cmd.Flags().StringP(flags.Config, "c", "", "Path to heimdall's configuration file.")

			if len(tc.confFile) != 0 {
				err = cmd.ParseFlags([]string{"--" + flags.Config, tc.confFile})
				require.NoError(t, err)
			}

			// WHEN
			err = validateConfig(cmd)

			// THEN
			tc.assert(t, err)
		})
	}
}

func TestRunValidateConfigCommand(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc       string
		confFile string
		expError string
	}{
		{uc: "invalid config", confFile: "doesnotexist.yaml", expError: "no such file or dir"},
		{uc: "valid config", confFile: "test_data/config.yaml"},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			exit, err := testsupport.PatchOSExit(t, func(int) {})
			require.NoError(t, err)

			cmd := NewValidateConfigCommand()

			buf := bytes.NewBuffer([]byte{})
			cmd.SetOut(buf)
			cmd.SetErr(buf)

			cmd.Flags().StringP(flags.Config, "c", "", "Path to heimdall's configuration file.")

			if len(tc.confFile) != 0 {
				err := cmd.ParseFlags([]string{"--" + flags.Config, tc.confFile})
				require.NoError(t, err)
			}

			// WHEN
			cmd.Run(cmd, []string{})

			log := buf.String()
			if len(tc.expError) != 0 {
				assert.Contains(t, log, tc.expError)
				assert.True(t, exit.Called)
				assert.Equal(t, 1, exit.Code)
			} else {
				assert.Contains(t, log, "Configuration is valid")
			}
		})
	}
}
