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

package secrets

import (
	"context"
	"errors"

	"github.com/dadrus/heimdall/internal/secrets/registry"
	"github.com/dadrus/heimdall/internal/secrets/types"
)

type (
	SecretKind  = types.SecretKind
	Secret      = types.Secret
	Credentials = types.Credentials

	Manager interface {
		ResolveSecret(ctx context.Context, source, ref string) (Secret, error)
		ResolveCredentials(ctx context.Context, source, ref string) (Credentials, error)
		Subscribe(source, ref string, cb func(context.Context) error) (unsubscribe func(), err error)
	}
)

var (
	ErrProviderNotFound        = errors.New("secret provider not found")
	ErrSubscribeFailed         = errors.New("secret changes subscription failed")
	ErrUnsupportedProviderType = registry.ErrUnsupportedProviderType
	ErrSecretKindMismatch      = types.ErrSecretKindMismatch
)

const (
	SecretKindString     = types.SecretKindString
	SecretKindBytes      = types.SecretKindBytes
	SecretKindSigner     = types.SecretKindSigner
	SecretKindTrustStore = types.SecretKindTrustStore
)
