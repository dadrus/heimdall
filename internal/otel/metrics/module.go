// Copyright 2023 Dimitrij Drus <dadrus@gmx.de>
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

package metrics

import (
	"go.opentelemetry.io/contrib/instrumentation/host"
	"go.opentelemetry.io/contrib/instrumentation/runtime"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/otel/metrics/certificate"
)

var Module = fx.Options( // nolint: gochecknoglobals
	fx.Invoke(runtime.Start),
	fx.Invoke(host.Start),
	fx.Provide(
		fx.Annotate(
			certificate.NewObserver,
			fx.OnStart(func(co certificate.Observer) error { return co.Start() }),
		),
	),
)
