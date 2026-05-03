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

	Reference struct {
		Source      string
		Selector    string
		Namespace   string
		RuleContext bool
	}

	Manager interface {
		ResolveSecret(ctx context.Context, ref Reference) (Secret, error)
		ResolveSecretSet(ctx context.Context, ref Reference) ([]Secret, error)
		ResolveCredentials(ctx context.Context, ref Reference) (Credentials, error)
		Subscribe(ref Reference, cb func(context.Context) error) (unsubscribe func(), err error)
	}
)

var (
	ErrProviderNotFound        = errors.New("secret provider not found")
	ErrSubscribeFailed         = errors.New("secret changes subscription failed")
	ErrSecretSourceForbidden   = errors.New("secret source forbidden in rule context")
	ErrUnsupportedProviderType = registry.ErrUnsupportedProviderType
	ErrSecretKindMismatch      = types.ErrSecretKindMismatch
	ErrUnsupportedOperation    = types.ErrUnsupportedOperation
)

const (
	SecretKindString        = types.SecretKindString
	SecretKindSymmetricKey  = types.SecretKindSymmetricKey
	SecretKindAsymmetricKey = types.SecretKindAsymmetricKey
	SecretKindTrustStore    = types.SecretKindTrustStore
)

func InternalRef(source, selector string) Reference {
	return Reference{
		Source:   source,
		Selector: selector,
	}
}

func RuleRef(namespace, source, selector string) Reference {
	return Reference{
		Source:      source,
		Selector:    selector,
		Namespace:   namespace,
		RuleContext: true,
	}
}
