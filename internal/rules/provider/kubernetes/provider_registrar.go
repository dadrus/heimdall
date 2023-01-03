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

package kubernetes

import (
	"context"

	"github.com/rs/zerolog"
	"go.uber.org/fx"
	"k8s.io/client-go/rest"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/event"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type ConfigFactory func() (*rest.Config, error)

type registrationArguments struct {
	fx.In

	Lifecycle fx.Lifecycle
	Config    *config.Configuration
	K8sConfig ConfigFactory
	Queue     event.RuleSetChangedEventQueue
}

func registerProvider(args registrationArguments, logger zerolog.Logger) error {
	if args.Config.Rules.Providers.Kubernetes == nil {
		return nil
	}

	k8sConf, err := args.K8sConfig()
	if err != nil {
		return errorchain.NewWithMessage(heimdall.ErrInternal, "failed to create kubernetes provider").
			CausedBy(err)
	}

	provider, err := newProvider(args.Config.Rules.Providers.Kubernetes, k8sConf, args.Queue, logger)
	if err != nil {
		return errorchain.NewWithMessage(heimdall.ErrInternal, "failed to create kubernetes provider").
			CausedBy(err)
	}

	logger.Info().
		Str("_rule_provider_type", ProviderType).
		Msg("Rule provider configured.")

	args.Lifecycle.Append(
		fx.Hook{
			OnStart: func(ctx context.Context) error { return provider.Start(ctx) },
			OnStop:  func(ctx context.Context) error { return provider.Stop(ctx) },
		},
	)

	return nil
}
