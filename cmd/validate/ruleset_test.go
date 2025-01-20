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

	"github.com/drone/envsubst/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/cmd/flags"
	"github.com/dadrus/heimdall/internal/x/pkix/pemx"
	"github.com/dadrus/heimdall/internal/x/stringx"
	"github.com/dadrus/heimdall/internal/x/testsupport"
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

	raw, err := os.ReadFile("test_data/config.yaml")
	require.NoError(t, err)

	content, err := envsubst.EvalEnv(stringx.ToString(raw))
	require.NoError(t, err)

	err = os.WriteFile(configFile, []byte(content), 0o600)
	require.NoError(t, err)

	for _, tc := range []struct {
		uc        string
		confFile  string
		rulesFile string
		expError  error
	}{
		{
			uc:       "no config provided",
			expError: ErrNoConfigFile,
		},
		{
			uc:       "invalid configconfig file",
			confFile: "doesnotexist.yaml",
			expError: os.ErrNotExist,
		},
		{
			uc:        "invalid rule set file",
			confFile:  configFile,
			rulesFile: "doesnotexist.yaml",
			expError:  os.ErrNotExist,
		},
		{
			uc:        "everything is valid",
			confFile:  configFile,
			rulesFile: "test_data/valid-ruleset.yaml",
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			cmd := NewValidateRulesCommand()
			cmd.Flags().StringP(flags.Config, "c", "", "Path to heimdall's configuration file.")

			if len(tc.confFile) != 0 {
				err := cmd.ParseFlags([]string{"--" + flags.Config, tc.confFile})
				require.NoError(t, err)
			}

			// WHEN
			err := validateRuleSet(cmd, []string{tc.rulesFile})

			// THEN
			if tc.expError != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.expError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestRunValidateRulesCommand(t *testing.T) {
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

	raw, err := os.ReadFile("test_data/config.yaml")
	require.NoError(t, err)

	content, err := envsubst.EvalEnv(stringx.ToString(raw))
	require.NoError(t, err)

	err = os.WriteFile(configFile, []byte(content), 0o600)
	require.NoError(t, err)

	for _, tc := range []struct {
		uc        string
		confFile  string
		rulesFile string
		proxyMode bool
		expError  string
	}{
		{
			uc:       "validation fails",
			expError: "no config file",
		},
		{
			uc:        "everything is valid for decision mode usage",
			confFile:  configFile,
			rulesFile: "test_data/valid-ruleset.yaml",
		},
		{
			uc:        "invalid for proxy usage",
			proxyMode: true,
			confFile:  configFile,
			rulesFile: "test_data/invalid-ruleset-for-proxy-usage.yaml",
			expError:  "requires forward_to",
		},
		{
			uc:        "everything is valid for proxy mode usage",
			proxyMode: true,
			confFile:  configFile,
			rulesFile: "test_data/valid-ruleset.yaml",
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			exit, err := testsupport.PatchOSExit(t, func(int) {})
			require.NoError(t, err)

			cmd := NewValidateRulesCommand()

			buf := bytes.NewBuffer([]byte{})
			cmd.SetOut(buf)
			cmd.SetErr(buf)

			cmd.Flags().StringP(flags.Config, "c", "", "Path to heimdall's configuration file.")

			var args []string

			if len(tc.confFile) != 0 {
				args = append(args, "--"+flags.Config, tc.confFile)
			}

			if tc.proxyMode {
				args = append(args, "--"+validationForProxyMode)
			}

			err = cmd.ParseFlags(args)
			require.NoError(t, err)

			// WHEN
			cmd.Run(cmd, []string{tc.rulesFile})

			log := buf.String()
			if len(tc.expError) != 0 {
				assert.Contains(t, log, tc.expError)
				assert.True(t, exit.Called)
				assert.Equal(t, 1, exit.Code)
			} else {
				assert.Contains(t, log, "Rule set is valid")
			}
		})
	}
}
