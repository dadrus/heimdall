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

package authorizers

import (
	"errors"
	"sync"

	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var (
	ErrUnsupportedAuthorizerType = errors.New("authorizer type unsupported")

	// by intention. Used only during application bootstrap.
	authorizerTypeFactories   []AuthorizerTypeFactory //nolint:gochecknoglobals
	authorizerTypeFactoriesMu sync.RWMutex            //nolint:gochecknoglobals
)

type AuthorizerTypeFactory func(id string, typ string, config map[string]any) (bool, Authorizer, error)

func registerTypeFactory(factory AuthorizerTypeFactory) {
	authorizerTypeFactoriesMu.Lock()
	defer authorizerTypeFactoriesMu.Unlock()

	if factory == nil {
		panic("RegisterAuthorizerType factory is nil")
	}

	authorizerTypeFactories = append(authorizerTypeFactories, factory)
}

func CreatePrototype(id string, typ string, config map[string]any) (Authorizer, error) {
	authorizerTypeFactoriesMu.RLock()
	defer authorizerTypeFactoriesMu.RUnlock()

	for _, create := range authorizerTypeFactories {
		if ok, at, err := create(id, typ, config); ok {
			return at, err
		}
	}

	return nil, errorchain.NewWithMessagef(ErrUnsupportedAuthorizerType, "'%s'", typ)
}
