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

package template

import (
	"github.com/dadrus/heimdall/internal/secrets"
)

const defaultTemplateName = "Heimdall"

type Option func(*options)

type options struct {
	name             string
	resolver         secrets.Resolver
	secretsForbidden bool
}

func WithName(name string) Option {
	return func(opts *options) {
		if len(name) != 0 {
			opts.name = name
		}
	}
}

func WithSecretResolver(resolver secrets.Resolver) Option {
	return func(opts *options) {
		if resolver != nil {
			opts.resolver = resolver
		}
	}
}

func WithSecretsForbidden() Option {
	return func(opts *options) {
		opts.secretsForbidden = true
	}
}

func applyOptions(opts ...Option) options {
	cfg := options{name: defaultTemplateName}

	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	return cfg
}
