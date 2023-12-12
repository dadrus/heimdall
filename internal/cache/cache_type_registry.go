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
	"errors"
	"sync"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var (
	ErrUnsupportedCacheType  = errors.New("cache type unsupported")
	ErrConnectionCheckFailed = errors.New("cache connection failed")

	// by intention. Used only during application bootstrap.
	cacheTypeFactories   []TypeFactory //nolint:gochecknoglobals
	cacheTypeFactoriesMu sync.RWMutex  //nolint:gochecknoglobals
)

type TypeFactory func(typ string, cfg *config.Configuration) (bool, Cache, error)

func registerCacheTypeFactory(factory TypeFactory) {
	cacheTypeFactoriesMu.Lock()
	defer cacheTypeFactoriesMu.Unlock()

	if factory == nil {
		panic("RegisterCacheType factory is nil")
	}

	cacheTypeFactories = append(cacheTypeFactories, factory)
}

func CreateCachePrototype(typ string, config *config.Configuration) (Cache, error) {
	cacheTypeFactoriesMu.RLock()
	defer cacheTypeFactoriesMu.RUnlock()

	for _, create := range cacheTypeFactories {
		if ok, at, err := create(typ, config); ok {
			return at, err
		}
	}

	return nil, errorchain.NewWithMessagef(ErrUnsupportedCacheType, "'%s'", typ)
}
