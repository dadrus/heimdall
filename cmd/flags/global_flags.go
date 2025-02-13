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

const (
	Config                  = "config"
	EnvironmentConfigPrefix = "env-config-prefix"

	SkipAllSecurityEnforcement          = "insecure"
	SkipSecureTrustedProxiesEnforcement = "insecure-skip-secure-trusted-proxies-enforcement"
	SkipSecureDefaultRuleEnforcement    = "insecure-skip-secure-default-rule-enforcement"
	SkipAllTLSEnforcement               = "insecure-skip-all-tls-enforcement"
	SkipIngressTLSEnforcement           = "insecure-skip-ingress-tls-enforcement"
	SkipEgressTLSEnforcement            = "insecure-skip-egress-tls-enforcement"
	SkipUpstreamTLSEnforcement          = "insecure-skip-upstream-tls-enforcement"
)

var InsecureFlags = []string{ //nolint: gochecknoglobals
	SkipAllSecurityEnforcement,
	SkipSecureTrustedProxiesEnforcement,
	SkipSecureDefaultRuleEnforcement,
	SkipAllTLSEnforcement,
	SkipIngressTLSEnforcement,
	SkipEgressTLSEnforcement,
	SkipUpstreamTLSEnforcement,
}
