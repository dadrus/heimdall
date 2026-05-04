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

package registry

import (
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/encoding"
	"github.com/dadrus/heimdall/internal/secrets/types"
)

type (
	ProviderArgs struct {
		SourceName     string
		Config         map[string]any
		Logger         zerolog.Logger
		DecoderFactory encoding.DecoderFactory
	}

	Factory interface {
		Create(args ProviderArgs) (types.Provider, error)
	}

	FactoryFunc func(args ProviderArgs) (types.Provider, error)
)

func (f FactoryFunc) Create(args ProviderArgs) (types.Provider, error) {
	return f(args)
}
