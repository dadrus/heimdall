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

package cache

import (
	"context"
	"time"

	"github.com/dadrus/heimdall/internal/config"
)

// by intention. Used only during application bootstrap.
func init() { // nolint: gochecknoinits
	registerCacheTypeFactory(
		func(typ string, conf *config.Configuration) (bool, Cache, error) {
			if typ != CacheNoop {
				return false, nil, nil
			}

			cache := noopCache{}

			return true, cache, nil
		})
}

type noopCache struct{}

func (noopCache) Check(_ context.Context) error {
	return nil
}

func (noopCache) Get(_ context.Context, _ string) any { return nil }

func (noopCache) Set(_ context.Context, _ string, _ any, _ time.Duration) {}

func (noopCache) Delete(_ context.Context, _ string) {}

func (noopCache) Start(_ context.Context) error { return nil }

func (noopCache) Stop(_ context.Context) error { return nil }
