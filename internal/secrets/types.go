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

	"github.com/dadrus/heimdall/internal/secrets/types"
)

type (
	Secret              = types.Secret
	StringSecret        = types.StringSecret
	SymmetricKeySecret  = types.SymmetricKeySecret
	AsymmetricKeySecret = types.AsymmetricKeySecret
	Credentials         = types.Credentials
	CertificateBundle   = types.CertificateBundle

	Reference = types.Reference

	UpdateFunc[T any] func(context.Context, T) error

	Handle[T any] interface {
		Get() (T, bool)
		OnUpdate(callback UpdateFunc[T])
	}

	SecretHandle interface {
		Handle[Secret]
	}

	SecretSetHandle interface {
		Handle[[]Secret]
	}

	CredentialsHandle interface {
		Handle[Credentials]
	}

	CertificateBundleHandle interface {
		Handle[CertificateBundle]
	}

	ReadyAwaiter interface {
		AwaitReady(ctx context.Context) error
	}

	Resolver interface {
		Secret(ref Reference) (SecretHandle, error)
		SecretSet(ref Reference) (SecretSetHandle, error)
		Credentials(ref Reference) (CredentialsHandle, error)
		CertificateBundle(ref Reference) (CertificateBundleHandle, error)
	}

	ScopedResolver interface {
		Resolver
		ReadyAwaiter
		Release()
	}

	ScopeOption func(*scope)

	ScopedResolverFactory interface {
		Create(opts ...ScopeOption) ScopedResolver
	}
)

func WithNamespace(namespace string) ScopeOption {
	return func(scp *scope) {
		scp.namespace = namespace
		scp.refFactory = namespacedRuleRef(namespace)
	}
}

func WithID(id string) ScopeOption {
	return func(scp *scope) {
		scp.id = id
	}
}
