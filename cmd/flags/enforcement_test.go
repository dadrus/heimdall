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

package flags

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnforcementSettings(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		args                        []string
		enforceSecureDefaultRule    bool
		enforceSecureTrustedProxies bool
		enforceManagementTLS        bool
		enforceIngressTLS           bool
		enforceEgressTLS            bool
		enforceUpstreamTLS          bool
	}{
		"should skip security settings entirely": {
			args: []string{"--" + SkipAllSecurityEnforcement},
		},
		"should skip TLS enforcement only": {
			args:                        []string{"--" + SkipAllTLSEnforcement},
			enforceSecureDefaultRule:    true,
			enforceSecureTrustedProxies: true,
		},
		"should not enforce secure default rule": {
			args:                        []string{"--" + SkipSecureDefaultRuleEnforcement},
			enforceManagementTLS:        true,
			enforceIngressTLS:           true,
			enforceEgressTLS:            true,
			enforceUpstreamTLS:          true,
			enforceSecureTrustedProxies: true,
		},
		"should not enforce secure trusted proxies": {
			args:                     []string{"--" + SkipSecureTrustedProxiesEnforcement},
			enforceSecureDefaultRule: true,
			enforceManagementTLS:     true,
			enforceIngressTLS:        true,
			enforceEgressTLS:         true,
			enforceUpstreamTLS:       true,
		},
		"should not enforce ingress TLS": {
			args:                        []string{"--" + SkipIngressTLSEnforcement},
			enforceSecureDefaultRule:    true,
			enforceSecureTrustedProxies: true,
			enforceManagementTLS:        true,
			enforceEgressTLS:            true,
			enforceUpstreamTLS:          true,
		},
		"should not enforce egress TLS": {
			args:                        []string{"--" + SkipEgressTLSEnforcement},
			enforceSecureDefaultRule:    true,
			enforceSecureTrustedProxies: true,
			enforceManagementTLS:        true,
			enforceIngressTLS:           true,
			enforceUpstreamTLS:          true,
		},
		"should not enforce upstream TLS": {
			args:                        []string{"--" + SkipUpstreamTLSEnforcement},
			enforceSecureDefaultRule:    true,
			enforceSecureTrustedProxies: true,
			enforceManagementTLS:        true,
			enforceIngressTLS:           true,
			enforceEgressTLS:            true,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			cmd := &cobra.Command{Use: "test"}
			cmd.PersistentFlags().Bool(SkipAllSecurityEnforcement, false, "")
			cmd.PersistentFlags().Bool(SkipAllTLSEnforcement, false, "")
			cmd.PersistentFlags().Bool(SkipIngressTLSEnforcement, false, "")
			cmd.PersistentFlags().Bool(SkipEgressTLSEnforcement, false, "")
			cmd.PersistentFlags().Bool(SkipUpstreamTLSEnforcement, false, "")
			cmd.PersistentFlags().Bool(SkipSecureDefaultRuleEnforcement, false, "")
			cmd.PersistentFlags().Bool(SkipSecureTrustedProxiesEnforcement, false, "")

			cmd.SetArgs(tc.args)

			res, err := cmd.ExecuteC()
			require.NoError(t, err)

			es := EnforcementSettings(res)
			assert.Equal(t, tc.enforceSecureDefaultRule, es.EnforceSecureDefaultRule)
			assert.Equal(t, tc.enforceSecureTrustedProxies, es.EnforceSecureTrustedProxies)
			assert.Equal(t, tc.enforceIngressTLS, es.EnforceIngressTLS)
			assert.Equal(t, tc.enforceEgressTLS, es.EnforceEgressTLS)
			assert.Equal(t, tc.enforceUpstreamTLS, es.EnforceUpstreamTLS)
		})
	}
}
