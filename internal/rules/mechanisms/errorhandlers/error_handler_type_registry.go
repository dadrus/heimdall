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

package errorhandlers

import (
	"errors"
	"sync"

	"github.com/dadrus/heimdall/internal/keyholder"
	"github.com/dadrus/heimdall/internal/otel/metrics/certificate"
	"github.com/dadrus/heimdall/internal/watcher"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var (
	ErrUnsupportedErrorHandlerType = errors.New("error handler type unsupported")

	errorHandlerTypeFactories   []TypeFactory // nolint: gochecknoglobals
	errorHandlerTypeFactoriesMu sync.RWMutex  // nolint: gochecknoglobals
)

//go:generate mockery --name CreationContext --structname CreationContextMock  --inpackage --testonly

type CreationContext interface {
	Watcher() watcher.Watcher
	KeyHolderRegistry() keyholder.Registry
	CertificateObserver() certificate.Observer
}

type TypeFactory func(ctx CreationContext, id string, typ string, c map[string]any) (bool, ErrorHandler, error)

func registerTypeFactory(factory TypeFactory) {
	errorHandlerTypeFactoriesMu.Lock()
	defer errorHandlerTypeFactoriesMu.Unlock()

	if factory == nil {
		panic("RegisterErrorHandler factory is nil")
	}

	errorHandlerTypeFactories = append(errorHandlerTypeFactories, factory)
}

func CreatePrototype(ctx CreationContext, id string, typ string, config map[string]any) (ErrorHandler, error) {
	errorHandlerTypeFactoriesMu.RLock()
	defer errorHandlerTypeFactoriesMu.RUnlock()

	for _, create := range errorHandlerTypeFactories {
		if ok, at, err := create(ctx, id, typ, config); ok {
			return at, err
		}
	}

	return nil, errorchain.NewWithMessagef(ErrUnsupportedErrorHandlerType, "'%s'", typ)
}
