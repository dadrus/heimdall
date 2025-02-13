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
	"github.com/spf13/cobra"

	"github.com/dadrus/heimdall/internal/config"
)

func EnforcementSettings(cmd *cobra.Command) config.EnforcementSettings {
	insecure, _ := cmd.Flags().GetBool(SkipAllSecurityEnforcement)
	insecureDefaultRule, _ := cmd.Flags().GetBool(SkipSecureDefaultRuleEnforcement)
	insecureTrustedProxies, _ := cmd.Flags().GetBool(SkipSecureTrustedProxiesEnforcement)
	insecureNotTLS, _ := cmd.Flags().GetBool(SkipAllTLSEnforcement)
	insecureNoIngressTLS, _ := cmd.Flags().GetBool(SkipIngressTLSEnforcement)
	insecureNoEgressTLS, _ := cmd.Flags().GetBool(SkipEgressTLSEnforcement)
	insecureNoUpstreamTLS, _ := cmd.Flags().GetBool(SkipUpstreamTLSEnforcement)

	if insecure {
		insecureDefaultRule = true
		insecureNotTLS = true
		insecureTrustedProxies = true
	}

	if insecureNotTLS {
		insecureNoIngressTLS = true
		insecureNoEgressTLS = true
		insecureNoUpstreamTLS = true
	}

	return config.EnforcementSettings{
		EnforceSecureDefaultRule:    !insecureDefaultRule,
		EnforceSecureTrustedProxies: !insecureTrustedProxies,
		EnforceIngressTLS:           !insecureNoIngressTLS,
		EnforceEgressTLS:            !insecureNoEgressTLS,
		EnforceUpstreamTLS:          !insecureNoUpstreamTLS,
	}
}
