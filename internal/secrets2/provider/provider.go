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

package provider //nolint:revive

import (
	"context"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/encoding"
	"github.com/dadrus/heimdall/internal/secrets2/types"
)

var (
	ErrConfiguration             = types.ErrConfiguration
	ErrInternal                  = types.ErrInternal
	ErrSecretNotFound            = types.ErrSecretNotFound
	ErrSecretSetNotFound         = types.ErrSecretSetNotFound
	ErrCredentialsNotFound       = types.ErrCredentialsNotFound
	ErrCertificateBundleNotFound = types.ErrCertificateBundleNotFound
	ErrUnsupportedOperation      = types.ErrUnsupportedOperation
)

type SecretKind = types.SecretKind

const (
	SecretKindString            = types.SecretKindString
	SecretKindSymmetricKey      = types.SecretKindSymmetricKey
	SecretKindAsymmetricKey     = types.SecretKindAsymmetricKey
	SecretKindCertificateBundle = types.SecretKindCertificateBundle
	SecretKindCredentials       = types.SecretKindCredentials
)

type (
	Secret              = types.Secret
	StringSecret        = types.StringSecret
	SymmetricKeySecret  = types.SymmetricKeySecret
	AsymmetricKeySecret = types.AsymmetricKeySecret
	Credentials         = types.Credentials
	CertificateBundle   = types.CertificateBundle

	// Reference identifies a secret or credentials object required by a provider
	// to initialize its own runtime state.
	Reference = types.Reference

	// Selector identifies a provider-local secret, credentials object, or secret
	// set.
	Selector struct {
		// Value is the provider-local selector value.
		Value string
		// Namespace is optional and is used only by namespace-aware providers.
		// Providers that are not namespace-aware should ignore this value.
		Namespace string
	}

	// ChangeEvent reports changes detected by a provider.
	//
	// The event is source-scoped by the manager. Providers must not include or
	// infer the configured source name when reporting changes.
	//
	// If Selectors is empty, the event represents a source-wide change and all
	// subscriptions for the source may be notified. Otherwise, each selector
	// identifies one changed provider-local value. Namespace-aware providers may
	// set Selector.Namespace on individual selectors.
	ChangeEvent struct {
		Selectors []Selector
	}

	// ChangeObserver receives provider change events.
	//
	// The manager passes a source-scoped observer to each provider. Providers
	// call Notify after Start has succeeded and before Stop returns when they
	// detect changes to their backing data. Providers must stop producing events
	// before Stop returns.
	//
	// Implementations must not assume Notify blocks until all consumers have
	// processed the event.
	ChangeObserver interface {
		Notify(evt ChangeEvent)
	}

	// DependenciesResolver resolves provider configuration dependencies.
	//
	// A provider may resolve only references it returned from Dependencies.
	// The resolver is intended for provider runtime initialization and reload only.
	DependenciesResolver interface {
		// ResolveSecret resolves a Secret.
		ResolveSecret(ctx context.Context, ref Reference) (Secret, error)
		// ResolveCredentials resolves one Credentials object.
		ResolveCredentials(ctx context.Context, ref Reference) (Credentials, error)
		// ResolveCertificateBundle resolves a CertificateBundle object.
		ResolveCertificateBundle(ctx context.Context, ref Reference) (CertificateBundle, error)
	}

	// Args contains the dependencies required to create a provider
	// instance.
	Args struct {
		// Config is the provider configuration.
		Config map[string]any
		// Logger is the provider-scoped logger.
		Logger zerolog.Logger
		// DecoderFactory should be used to decode provider configuration.
		DecoderFactory encoding.DecoderFactory
		// Observer should be used to report changes to the secrets the provider
		// manages.
		Observer ChangeObserver
		// Resolver should be used to resolve secrets, the provider implementation
		// requires.
		Resolver DependenciesResolver
	}

	// Factory creates provider instances from static configuration.
	Factory interface {
		// Create must return a provider with fully decoded and validated static
		// configuration. If the configuration is malformed or unsupported, Create
		// must return an error.
		// Create must not resolve secrets, connect to backend systems, start watchers,
		// or perform other runtime I/O. Runtime work belongs in Provider.Start
		// and Provider.Stop.
		Create(args Args) (Provider, error)
	}

	// FactoryFunc adapts a function to Factory.
	FactoryFunc func(args Args) (Provider, error)

	// Provider is a configured secret source runtime.
	//
	// A provider instance is created once by its factory, started by the manager,
	// optionally restarted when one of its Dependencies changes, and finally
	// stopped by the manager. Providers must be safe for concurrent calls to
	// GetSecret, GetSecretSet, and GetCredentials. Providers must also support
	// repeated Start/Stop cycles.
	Provider interface {
		// Type returns the provider backend type.
		Type() string

		// Dependencies returns provider configuration secret references this
		// provider needs to resolve during Start.
		//
		// The returned references must be complete, normalized, side-effect free,
		// and must not expose mutable provider-internal state. The returned set
		// must include every reference the provider may resolve through its
		// DependenciesResolver.
		//
		// The manager uses these references to validate the source dependency
		// graph, reject cycles, start sources in dependency order, and schedule
		// Reload when a dependency changes.
		Dependencies() []Reference

		// IsNamespaceAware returns whether this provider interprets Selector.Namespace.
		IsNamespaceAware() bool

		// Start starts the provider.
		//
		// Start may resolve Dependencies through the provider's DependenciesResolver,
		// connect to backend systems, initialize runtime state, and start provider
		// watchers. If Start fails, the manager treats the source as not started.
		Start(ctx context.Context) error

		// Stop stops the provider and releases runtime resources.
		//
		// Stop must stop provider-owned watchers and must ensure no further change
		// events are emitted after Stop returns. Stop should be idempotent.
		Stop(ctx context.Context) error

		// GetSecret returns the secret for the given provider-local selector.
		//
		// Providers that do not support secrets should return ErrUnsupportedOperation.
		// If a secret is not found, GetSecret must return ErrSecretNotFound.
		GetSecret(ctx context.Context, selector Selector) (Secret, error)

		// GetSecretSet returns the secret set for the given provider-local selector.
		//
		// Providers that do not support secret sets should return ErrUnsupportedOperation.
		// If a secret set is not available, GetSecretSet must return ErrSecretSetNotFound.
		GetSecretSet(ctx context.Context, selector Selector) ([]Secret, error)

		// GetCredentials returns the credentials for the given provider-local
		// selector.
		//
		// Providers that do not support credentials should return ErrUnsupportedOperation.
		// If a credentials object not found, GetCredentials must return ErrCredentialsNotFound.
		GetCredentials(ctx context.Context, selector Selector) (Credentials, error)

		// GetCertificateBundle returns a certificate bundle for the given provider-local
		// selector.
		//
		// Providers that do not support certificate bundles should return ErrUnsupportedOperation.
		// If a certificate bundle object is not found, GetCertificateBundle must return
		// ErrCertificateBundleNotFound.
		GetCertificateBundle(ctx context.Context, selector Selector) (CertificateBundle, error)
	}
)

var (
	NewStringSecret        = types.NewStringSecret
	NewSymmetricKeySecret  = types.NewSymmetricKeySecret
	NewAsymmetricKeySecret = types.NewAsymmetricKeySecret
	NewCredentials         = types.NewCredentials
	NewCertificateBundle   = types.NewCertificateBundle
)

func (f FactoryFunc) Create(args Args) (Provider, error) {
	return f(args)
}
