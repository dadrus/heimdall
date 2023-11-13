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

package provider

import (
	"github.com/rs/zerolog"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/rules/provider/cloudblob"
	"github.com/dadrus/heimdall/internal/rules/provider/filesystem"
	"github.com/dadrus/heimdall/internal/rules/provider/httpendpoint"
	"github.com/dadrus/heimdall/internal/rules/provider/kubernetes"
)

// Module is used on app bootstrap.
// nolint: gochecknoglobals
var Module = fx.Options(
	fx.Invoke(checkRuleProvider),
	filesystem.Module,
	httpendpoint.Module,
	cloudblob.Module,
	kubernetes.Module,
)

func checkRuleProvider(logger zerolog.Logger, conf *config.Configuration) {
	var ruleProviderConfigured bool

	switch {
	case conf.Providers.FileSystem != nil:
		ruleProviderConfigured = true
	case conf.Providers.HTTPEndpoint != nil:
		ruleProviderConfigured = true
	case conf.Providers.CloudBlob != nil:
		ruleProviderConfigured = true
	case conf.Providers.Kubernetes != nil:
		ruleProviderConfigured = true
	}

	if !ruleProviderConfigured {
		logger.Warn().Msg("No rule provider configured. Only defaults will be used.")
	}
}
