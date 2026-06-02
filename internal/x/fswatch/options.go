// Copyright 2026 Dimitrij Drus
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package fswatch

import "github.com/rs/zerolog"

type config struct {
	logger zerolog.Logger
}

// Option configures a Watcher.
type Option func(*config)

// WithLogger configures the logger used by the watcher.
func WithLogger(logger zerolog.Logger) Option {
	return func(cfg *config) {
		cfg.logger = logger
	}
}

func applyOptions(opts []Option) config {
	cfg := config{
		logger: zerolog.Nop(),
	}

	for _, opt := range opts {
		opt(&cfg)
	}

	return cfg
}
