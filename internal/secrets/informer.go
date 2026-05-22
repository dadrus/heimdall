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
	"crypto/x509"
	"errors"
)

var ErrTooManyInformerOptions = errors.New("too many informer options provided")

type (
	SecretConverter[T any]      func(Secret) (T, error)
	CredentialsConverter[T any] func(Credentials) (T, error)
)

type (
	SecretUpdateFunc[T any]      func(context.Context, Secret, T)
	CredentialsUpdateFunc[T any] func(context.Context, Credentials, T)
	CertificateBundleUpdateFunc  func(context.Context, CertificateBundle, *x509.CertPool)
)

type InformerOptions[T any] struct {
	Converter   SecretConverter[T]
	ResolveMode ResolveMode
	OnUpdate    SecretUpdateFunc[T]
}

type SecretInformer[T any] struct {
	handle    SecretHandle
	converter SecretConverter[T]
}

func NewSecretInformer[T any](
	ctx context.Context,
	resolver Resolver,
	reference Reference,
	opts ...InformerOptions[T],
) (*SecretInformer[T], error) {
	cfg, err := singleInformerOption(opts)
	if err != nil {
		return nil, err
	}

	converter := cfg.Converter
	if converter == nil {
		converter = identitySecretConverter[T]
	}

	hdl, err := resolver.Secret(ctx, reference, resolveOptionsForMode(cfg.ResolveMode)...)
	if err != nil {
		return nil, err
	}

	informer := &SecretInformer[T]{
		handle:    hdl,
		converter: converter,
	}

	if cfg.OnUpdate != nil {
		hdl.OnUpdate(func(ctx context.Context, secret Secret) error {
			value, err := converter(secret)
			if err != nil {
				return errors.Join(ErrSecretConversionFailed, err)
			}

			cfg.OnUpdate(ctx, secret, value)

			return nil
		})
	}

	return informer, nil
}

func (i *SecretInformer[T]) Get(ctx context.Context) (T, bool) {
	secret, ok := i.handle.Get(ctx)
	if !ok {
		var zero T

		return zero, false
	}

	value, err := i.converter(secret)
	if err != nil {
		var zero T

		return zero, false
	}

	return value, true
}

type CredentialsInformerOptions[T any] struct {
	Converter   CredentialsConverter[T]
	ResolveMode ResolveMode
	OnUpdate    CredentialsUpdateFunc[T]
}

type CredentialsInformer[T any] struct {
	handle    CredentialsHandle
	converter CredentialsConverter[T]
}

func NewCredentialsInformer[T any](
	ctx context.Context,
	resolver Resolver,
	reference Reference,
	opts ...CredentialsInformerOptions[T],
) (*CredentialsInformer[T], error) {
	cfg, err := singleInformerOption(opts)
	if err != nil {
		return nil, err
	}

	converter := cfg.Converter
	if converter == nil {
		converter = identityCredentialsConverter[T]
	}

	hdl, err := resolver.Credentials(ctx, reference, resolveOptionsForMode(cfg.ResolveMode)...)
	if err != nil {
		return nil, err
	}

	informer := &CredentialsInformer[T]{
		handle:    hdl,
		converter: converter,
	}

	if cfg.OnUpdate != nil {
		hdl.OnUpdate(func(ctx context.Context, credentials Credentials) error {
			value, err := converter(credentials)
			if err != nil {
				return errors.Join(ErrSecretConversionFailed, err)
			}

			cfg.OnUpdate(ctx, credentials, value)

			return nil
		})
	}

	return informer, nil
}

func (i *CredentialsInformer[T]) Get(ctx context.Context) (T, bool) {
	credentials, ok := i.handle.Get(ctx)
	if !ok {
		var zero T

		return zero, false
	}

	value, err := i.converter(credentials)
	if err != nil {
		var zero T

		return zero, false
	}

	return value, true
}

type CertificateBundleInformerOptions struct {
	ResolveMode ResolveMode
	OnUpdate    CertificateBundleUpdateFunc
}

type CertificateBundleInformer struct {
	handle CertificateBundleHandle
}

func NewCertificateBundleInformer(
	ctx context.Context,
	resolver Resolver,
	reference Reference,
	opts ...CertificateBundleInformerOptions,
) (*CertificateBundleInformer, error) {
	cfg, err := singleInformerOption(opts)
	if err != nil {
		return nil, err
	}

	hdl, err := resolver.CertificateBundle(ctx, reference, resolveOptionsForMode(cfg.ResolveMode)...)
	if err != nil {
		return nil, err
	}

	informer := &CertificateBundleInformer{
		handle: hdl,
	}

	if cfg.OnUpdate != nil {
		hdl.OnUpdate(func(ctx context.Context, bundle CertificateBundle) error {
			cfg.OnUpdate(ctx, bundle, bundle.CertPool())

			return nil
		})
	}

	return informer, nil
}

func (i *CertificateBundleInformer) Get(ctx context.Context) (*x509.CertPool, bool) {
	bundle, ok := i.handle.Get(ctx)
	if !ok {
		return nil, false
	}

	return bundle.CertPool(), true
}

func singleInformerOption[T any](opts []T) (T, error) {
	switch len(opts) {
	case 0:
		var zero T

		return zero, nil
	case 1:
		return opts[0], nil
	default:
		var zero T

		return zero, ErrTooManyInformerOptions
	}
}

func resolveOptionsForMode(mode ResolveMode) []ResolveOption {
	switch mode {
	case ResolveLazy:
		return []ResolveOption{Lazy()}
	case ResolveEager:
		return []ResolveOption{Eager()}
	default:
		return nil
	}
}

func identitySecretConverter[T any](secret Secret) (T, error) {
	value, ok := any(secret).(T)
	if !ok {
		var zero T

		return zero, ErrSecretConversionFailed
	}

	return value, nil
}

func identityCredentialsConverter[T any](credentials Credentials) (T, error) {
	value, ok := any(credentials).(T)
	if !ok {
		var zero T

		return zero, ErrSecretConversionFailed
	}

	return value, nil
}
