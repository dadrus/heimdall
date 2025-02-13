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

	"github.com/drone/envsubst/v2"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/cmd/flags"
	"github.com/dadrus/heimdall/internal/x/pkix/pemx"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

func TestValidateRuleset(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	pemBytes, err := pemx.BuildPEM(
		pemx.WithECDSAPrivateKey(privKey, pemx.WithHeader("X-Key-ID", "key")),
	)
	require.NoError(t, err)

	testDir := t.TempDir()
	pemFile := filepath.Join(testDir, "keystore.pem")
	configFile := filepath.Join(testDir, "test-config.yaml")

	t.Setenv("TEST_KEYSTORE_FILE", pemFile)

	err = os.WriteFile(pemFile, pemBytes, 0o600)
	require.NoError(t, err)

	raw, err := os.ReadFile("test_data/config-valid.yaml")
	require.NoError(t, err)

	content, err := envsubst.EvalEnv(stringx.ToString(raw))
	require.NoError(t, err)

	err = os.WriteFile(configFile, []byte(content), 0o600)
	require.NoError(t, err)

	for uc, tc := range map[string]struct {
		confFile  string
		rulesFile string
		proxyMode bool
		expError  string
	}{
		"no config provided": {
			expError: "no config file provided",
		},
		"invalid configconfig file": {
			confFile: "doesnotexist.yaml",
			expError: "no such file or directory",
		},
		"invalid rule set file": {
			confFile:  configFile,
			rulesFile: "doesnotexist.yaml",
			expError:  "no such file or directory",
		},
		"everything is valid for decision mode usage": {
			confFile:  configFile,
			rulesFile: "test_data/ruleset-valid.yaml",
		},
		"invalid for proxy usage": {
			proxyMode: true,
			confFile:  configFile,
			rulesFile: "test_data/ruleset-invalid-for-proxy-usage.yaml",
			expError:  "requires forward_to",
		},
		"everything is valid for proxy mode usage": {
			proxyMode: true,
			confFile:  configFile,
			rulesFile: "test_data/ruleset-valid.yaml",
		},
		"using http scheme for upstream communication": {
			proxyMode: true,
			confFile:  configFile,
			rulesFile: "test_data/ruleset-no-https-for-upstream.yaml",
			expError:  "'rules'[0].'forward_to'.'rewrite'.'scheme' must be https",
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			cmd := NewValidateRulesCommand()
			flags.RegisterGlobalFlags(cmd)

			if len(tc.confFile) != 0 {
				err = cmd.ParseFlags([]string{"--" + flags.Config, tc.confFile})
				require.NoError(t, err)
			}

			if tc.proxyMode {
				err = cmd.ParseFlags([]string{"--" + validationForProxyMode})
				require.NoError(t, err)
			}

			// WHEN
			err = validateRuleSet(cmd, []string{tc.rulesFile})

			// THEN
			if len(tc.expError) != 0 {
				require.Error(t, err)
				require.ErrorContains(t, err, tc.expError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
