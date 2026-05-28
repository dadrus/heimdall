// Copyright 2026 Dimitrij Drus <dadrus@gmx.de>
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

package secrets

import (
	"context"

	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var Module = fx.Options( //nolint:gochecknoglobals
	fx.Provide(
		fx.Annotate(
			NewManager,
			fx.OnStart(func(ctx context.Context, manager Manager) error { return manager.Start(ctx) }),
			fx.OnStop(func(ctx context.Context, manager Manager) error { return manager.Stop(ctx) }),
		),
		func(manager Manager) Resolver { return manager.Resolver() },
		func(manager Manager) ScopedResolverFactory { return manager.ScopedResolverFactory() },
	),
	fx.Invoke(
		fx.Annotate(
			func(Manager) {},
			fx.OnStart(func(ctx context.Context, manager Manager) error {
				if awaitable, ok := manager.(ReadyAwaiter); ok {
					return awaitable.AwaitReady(ctx)
				}

				return errorchain.NewWithMessage(
					ErrInternal,
					"secrets manager does not implement ReadyAwaiter, which is expected",
				)
			}),
		),
	),
)
