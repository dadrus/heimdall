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

import (
	"time"

	"github.com/rs/zerolog"
)

const (
	defaultEventDebounce    = 50 * time.Millisecond
	defaultMaxEventDebounce = time.Second
)

type config struct {
	logger           zerolog.Logger
	eventDebounce    time.Duration
	maxEventDebounce time.Duration
}

// Option configures a Watcher.
type Option func(*config)

// WithLogger configures the logger used by the watcher.
func WithLogger(logger zerolog.Logger) Option {
	return func(cfg *config) {
		cfg.logger = logger
	}
}

// WithEventDebounce configures how long normalized events for the same path are
// coalesced before they are dispatched. Use 0 to dispatch every normalized
// event immediately.
func WithEventDebounce(duration time.Duration) Option {
	return func(cfg *config) {
		if duration < 0 {
			duration = 0
		}

		cfg.eventDebounce = duration
	}
}

// WithMaxEventDebounce configures the maximum time a coalesced event may be
// delayed while more events for the same path keep arriving. Use 0 to disable
// the maximum delay.
func WithMaxEventDebounce(duration time.Duration) Option {
	return func(cfg *config) {
		if duration < 0 {
			duration = 0
		}

		cfg.maxEventDebounce = duration
	}
}

func applyOptions(opts []Option) config {
	cfg := config{
		logger:           zerolog.Nop(),
		eventDebounce:    defaultEventDebounce,
		maxEventDebounce: defaultMaxEventDebounce,
	}

	for _, opt := range opts {
		opt(&cfg)
	}

	return cfg
}
