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

package authenticators

import (
	"errors"
	"sync"

	"github.com/dadrus/heimdall/internal/keyholder"
	"github.com/dadrus/heimdall/internal/watcher"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var (
	ErrUnsupportedAuthenticatorType = errors.New("authenticator type unsupported")

	// by intention. Used only during application bootstrap.
	authenticatorTypeFactories   []TypeFactory //nolint:gochecknoglobals
	authenticatorTypeFactoriesMu sync.RWMutex  //nolint:gochecknoglobals
)

//go:generate mockery --name CreationContext --structname CreationContextMock  --inpackage --testonly

type CreationContext interface {
	Watcher() watcher.Watcher
	KeyHolderRegistry() keyholder.Registry
}

type TypeFactory func(ctx CreationContext, id string, typ string, config map[string]any) (bool, Authenticator, error)

func registerTypeFactory(factory TypeFactory) {
	authenticatorTypeFactoriesMu.Lock()
	defer authenticatorTypeFactoriesMu.Unlock()

	if factory == nil {
		panic("RegisterAuthenticatorType factory is nil")
	}

	authenticatorTypeFactories = append(authenticatorTypeFactories, factory)
}

func CreatePrototype(ctx CreationContext, id string, typ string, config map[string]any) (Authenticator, error) {
	authenticatorTypeFactoriesMu.RLock()
	defer authenticatorTypeFactoriesMu.RUnlock()

	for _, create := range authenticatorTypeFactories {
		if ok, at, err := create(ctx, id, typ, config); ok {
			return at, err
		}
	}

	return nil, errorchain.NewWithMessagef(ErrUnsupportedAuthenticatorType, "'%s'", typ)
}
