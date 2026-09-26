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

package ioprogress

import "time"

type config struct {
	requestReadTimeout         time.Duration
	requestBodyReadIdleTimeout time.Duration
	requestBodyReadMinRate     int64

	responseWriteTimeout     time.Duration
	responseWriteIdleTimeout time.Duration
	responseWriteMinRate     int64
}

type Option func(*config)

func WithRequestReadTimeout(timeout time.Duration) Option {
	return func(c *config) {
		c.requestReadTimeout = timeout
	}
}

func WithRequestBodyReadIdleTimeout(timeout time.Duration) Option {
	return func(c *config) {
		c.requestBodyReadIdleTimeout = timeout
	}
}

func WithRequestBodyReadMinRate(rate int64) Option {
	return func(c *config) {
		c.requestBodyReadMinRate = rate
	}
}

func WithResponseWriteTimeout(timeout time.Duration) Option {
	return func(c *config) {
		c.responseWriteTimeout = timeout
	}
}

func WithResponseWriteIdleTimeout(timeout time.Duration) Option {
	return func(c *config) {
		c.responseWriteIdleTimeout = timeout
	}
}

func WithResponseWriteMinRate(rate int64) Option {
	return func(c *config) {
		c.responseWriteMinRate = rate
	}
}

func newConfig(opts ...Option) *config {
	conf := new(config)
	for _, opt := range opts {
		opt(conf)
	}

	return conf
}
