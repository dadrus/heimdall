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

package secrets2

import (
	"context"
	"crypto/x509"
	"errors"
)

type (
	SecretConverter[T any]      func(Secret) (T, error)
	CredentialsConverter[T any] func(Credentials) (T, error)
)

type (
	SecretUpdateFunc[T any]      func(context.Context, Secret, T) error
	CredentialsUpdateFunc[T any] func(context.Context, Credentials, T) error
	CertificateBundleUpdateFunc  func(context.Context, CertificateBundle, *x509.CertPool) error
)

type SecretInformer[T any] struct {
	handle    SecretHandle
	converter SecretConverter[T]
}

func NewSecretInformer[T any](
	ctx context.Context,
	resolver Resolver,
	reference Reference,
	converter SecretConverter[T],
	opts ...ResolveOption,
) (*SecretInformer[T], error) {
	hdl, err := resolver.Secret(ctx, reference, opts...)
	if err != nil {
		return nil, err
	}

	return &SecretInformer[T]{
		handle:    hdl,
		converter: converter,
	}, nil
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

func (i *SecretInformer[T]) OnUpdate(cb SecretUpdateFunc[T]) {
	if cb == nil {
		return
	}

	i.handle.OnUpdate(func(ctx context.Context, secret Secret) error {
		value, err := i.converter(secret)
		if err != nil {
			return errors.Join(ErrSecretConversionFailed, err)
		}

		return cb(ctx, secret, value)
	})
}

type CredentialsInformer[T any] struct {
	handle    CredentialsHandle
	converter CredentialsConverter[T]
}

func NewCredentialsInformer[T any](
	ctx context.Context,
	resolver Resolver,
	reference Reference,
	converter CredentialsConverter[T],
	opts ...ResolveOption,
) (*CredentialsInformer[T], error) {
	hdl, err := resolver.Credentials(ctx, reference, opts...)
	if err != nil {
		return nil, err
	}

	return &CredentialsInformer[T]{
		handle:    hdl,
		converter: converter,
	}, nil
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

func (i *CredentialsInformer[T]) OnUpdate(cb CredentialsUpdateFunc[T]) {
	if cb == nil {
		return
	}

	i.handle.OnUpdate(func(ctx context.Context, credentials Credentials) error {
		value, err := i.converter(credentials)
		if err != nil {
			return errors.Join(ErrSecretConversionFailed, err)
		}

		return cb(ctx, credentials, value)
	})
}

type CertificateBundleInformer struct {
	handle CertificateBundleHandle
}

func NewCertificateBundleInformer(
	ctx context.Context,
	resolver Resolver,
	reference Reference,
	opts ...ResolveOption,
) (*CertificateBundleInformer, error) {
	hdl, err := resolver.CertificateBundle(ctx, reference, opts...)
	if err != nil {
		return nil, err
	}

	return &CertificateBundleInformer{
		handle: hdl,
	}, nil
}

func (i *CertificateBundleInformer) Get(ctx context.Context) (*x509.CertPool, bool) {
	bundle, ok := i.handle.Get(ctx)
	if !ok {
		return nil, false
	}

	return bundle.CertPool(), true
}

func (i *CertificateBundleInformer) OnUpdate(cb CertificateBundleUpdateFunc) {
	if cb == nil {
		return
	}

	i.handle.OnUpdate(func(ctx context.Context, credentials CertificateBundle) error {
		return cb(ctx, credentials, credentials.CertPool())
	})
}
