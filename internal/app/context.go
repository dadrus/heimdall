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

package app

import (
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/keyholder"
	"github.com/dadrus/heimdall/internal/otel/metrics/certificate"
	"github.com/dadrus/heimdall/internal/validation"
	"github.com/dadrus/heimdall/internal/watcher"
)

type Context interface {
	Watcher() watcher.Watcher
	KeyHolderRegistry() keyholder.Registry
	CertificateObserver() certificate.Observer
	Validator() validation.Validator
	Logger() zerolog.Logger
	Config() *config.Configuration
}
