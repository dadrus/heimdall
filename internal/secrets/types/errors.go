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

package types //nolint:revive

import (
	"errors"

	"github.com/dadrus/heimdall/internal/pipeline"
)

var (
	ErrUnsupportedProviderType   = errors.New("secret provider type unsupported")
	ErrSecretNotFound            = errors.New("secret not found")
	ErrSecretSetNotFound         = errors.New("secret set not found")
	ErrCredentialsNotFound       = errors.New("credentials not found")
	ErrCertificateBundleNotFound = errors.New("certificate bundle not found")
	ErrInvalidCredentialsPayload = errors.New("invalid credentials payload")
	ErrSourceNotFound            = errors.New("secret source not found")
	ErrDependencyNotDeclared     = errors.New("source dependency not declared")
	ErrUnsupportedOperation      = errors.New("unsupported operation")
	ErrConfiguration             = pipeline.ErrConfiguration
	ErrInternal                  = pipeline.ErrInternal
)
