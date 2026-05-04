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
	"strings"

	"github.com/dadrus/heimdall/internal/secrets/registry"
	"github.com/dadrus/heimdall/internal/secrets/types"
)

type (
	SecretKind          = types.SecretKind
	Secret              = types.Secret
	StringSecret        = types.StringSecret
	SymmetricKeySecret  = types.SymmetricKeySecret
	AsymmetricKeySecret = types.AsymmetricKeySecret
	TrustStoreSecret    = types.TrustStoreSecret
	Credentials         = types.Credentials

	Reference struct {
		Source      string
		Selector    string
		Namespace   string
		RuleContext bool
	}

	Manager interface {
		ResolveSecret(ctx context.Context, reference Reference) (Secret, error)
		ResolveSecretSet(ctx context.Context, reference Reference) ([]Secret, error)
		ResolveCredentials(ctx context.Context, reference Reference) (Credentials, error)
		Subscribe(reference Reference, cb func(context.Context) error) (unsubscribe func(), err error)
	}
)

var (
	ErrSubscribeFailed         = errors.New("secret changes subscription failed")
	ErrProviderNotFound        = errors.New("secret provider not found")
	ErrSecretSourceForbidden   = errors.New("secret source forbidden in rule context")
	ErrUnsupportedProviderType = registry.ErrUnsupportedProviderType
	ErrSecretNotFound          = types.ErrSecretNotFound
	ErrSecretKindMismatch      = types.ErrSecretKindMismatch
	ErrUnsupportedOperation    = types.ErrUnsupportedOperation
	ErrInvalidSecretPayload    = types.ErrInvalidSecretPayload
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

func (r Reference) Parent() Reference {
	if idx := strings.LastIndex(r.Selector, "/"); idx < 0 {
		r.Selector = ""
	} else {
		r.Selector = r.Selector[:idx]
	}

	return r
}
