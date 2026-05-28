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
	"sync"
	"sync/atomic"
)

type (
	Converter[S, T any] func(S) (T, error)

	UpdateCallback[S, T any] func(context.Context, S, T) error

	InformerOption[S, T any] func(*informerOptions[S, T])

	SecretConverter[T any]            = Converter[Secret, T]
	CredentialsConverter[T any]       = Converter[Credentials, T]
	CertificateBundleConverter[T any] = Converter[CertificateBundle, T]

	SecretUpdateFunc[T any]            = UpdateCallback[Secret, T]
	CredentialsUpdateFunc[T any]       = UpdateCallback[Credentials, T]
	CertificateBundleUpdateFunc[T any] = UpdateCallback[CertificateBundle, T]

	SecretInformerOption[T any]            = InformerOption[Secret, T]
	CredentialsInformerOption[T any]       = InformerOption[Credentials, T]
	CertificateBundleInformerOption[T any] = InformerOption[CertificateBundle, T]

	readinessRegistrar interface {
		registerReadiness(await func(context.Context) error)
	}
)

type informerOptions[S, T any] struct {
	converter Converter[S, T]
	onUpdate  UpdateCallback[S, T]
}

type informerState[T any] struct {
	value atomic.Value // stores T

	lastErr atomic.Pointer[storedError]

	readyOnce sync.Once
	readyCh   chan struct{}
}

type SecretInformer[T any] struct {
	state *informerState[T]
}

type CredentialsInformer[T any] struct {
	state *informerState[T]
}

type CertificateBundleInformer[T any] struct {
	state *informerState[T]
}

func WithConverter[S, T any](
	converter Converter[S, T],
) InformerOption[S, T] {
	return func(opts *informerOptions[S, T]) {
		opts.converter = converter
	}
}

func WithUpdateCallback[S, T any](
	callback UpdateCallback[S, T],
) InformerOption[S, T] {
	return func(opts *informerOptions[S, T]) {
		opts.onUpdate = callback
	}
}

func NewSecretInformer[T any](
	resolver Resolver,
	reference Reference,
	opts ...SecretInformerOption[T],
) (*SecretInformer[T], error) {
	cfg := applyInformerOptions(opts...)

	hdl, err := resolver.Secret(reference)
	if err != nil {
		return nil, err
	}

	state := newInformerState[T]()
	registerReadiness(hdl, state.awaitReady)

	hdl.OnUpdate(func(ctx context.Context, secret Secret) error {
		value, err := cfg.converter(secret)
		if err != nil {
			state.setLastErr(err)

			return err
		}

		state.store(value)

		if cfg.onUpdate != nil {
			return cfg.onUpdate(ctx, secret, value)
		}

		return nil
	})

	return &SecretInformer[T]{
		state: state,
	}, nil
}

func (i *SecretInformer[T]) Get() (T, bool) {
	return i.state.get()
}

func NewCredentialsInformer[T any](
	resolver Resolver,
	reference Reference,
	opts ...CredentialsInformerOption[T],
) (*CredentialsInformer[T], error) {
	cfg := applyInformerOptions(opts...)

	hdl, err := resolver.Credentials(reference)
	if err != nil {
		return nil, err
	}

	state := newInformerState[T]()
	registerReadiness(hdl, state.awaitReady)

	hdl.OnUpdate(func(ctx context.Context, credentials Credentials) error {
		value, err := cfg.converter(credentials)
		if err != nil {
			state.setLastErr(err)

			return err
		}

		state.store(value)

		if cfg.onUpdate != nil {
			return cfg.onUpdate(ctx, credentials, value)
		}

		return nil
	})

	return &CredentialsInformer[T]{
		state: state,
	}, nil
}

func (i *CredentialsInformer[T]) Get() (T, bool) {
	return i.state.get()
}

func NewCertificateBundleInformer[T any](
	resolver Resolver,
	reference Reference,
	opts ...CertificateBundleInformerOption[T],
) (*CertificateBundleInformer[T], error) {
	cfg := applyInformerOptions(opts...)

	hdl, err := resolver.CertificateBundle(reference)
	if err != nil {
		return nil, err
	}

	state := newInformerState[T]()
	registerReadiness(hdl, state.awaitReady)

	hdl.OnUpdate(func(ctx context.Context, bundle CertificateBundle) error {
		value, err := cfg.converter(bundle)
		if err != nil {
			state.setLastErr(err)

			return err
		}

		state.store(value)

		if cfg.onUpdate != nil {
			return cfg.onUpdate(ctx, bundle, value)
		}

		return nil
	})

	return &CertificateBundleInformer[T]{
		state: state,
	}, nil
}

func (i *CertificateBundleInformer[T]) Get() (T, bool) {
	return i.state.get()
}

func applyInformerOptions[S, T any](
	opts ...InformerOption[S, T],
) informerOptions[S, T] {
	var cfg informerOptions[S, T]

	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	if cfg.converter == nil {
		cfg.converter = identityConverter[S, T]
	}

	return cfg
}

func newInformerState[T any]() *informerState[T] {
	return &informerState[T]{
		readyCh: make(chan struct{}),
	}
}

func (s *informerState[T]) store(value T) {
	s.value.Store(value)
	s.setLastErr(nil)

	s.readyOnce.Do(func() {
		close(s.readyCh)
	})
}

func (s *informerState[T]) get() (T, bool) {
	value, ok := s.value.Load().(T)

	return value, ok
}

func (s *informerState[T]) awaitReady(ctx context.Context) error {
	select {
	case <-s.readyCh:
		return nil
	default:
	}

	select {
	case <-s.readyCh:
		return nil

	case <-ctx.Done():
		if err := s.getLastErr(); err != nil {
			return err
		}

		return ctx.Err()
	}
}

func (s *informerState[T]) setLastErr(err error) {
	if err == nil {
		s.lastErr.Store(nil)

		return
	}

	s.lastErr.Store(&storedError{err: err})
}

func (s *informerState[T]) getLastErr() error {
	stored := s.lastErr.Load()
	if stored == nil {
		return nil
	}

	return stored.err
}

func identityConverter[S, T any](source S) (T, error) {
	value, ok := any(source).(T)
	if !ok {
		var zero T

		return zero, ErrSecretConversionFailed
	}

	return value, nil
}

func registerReadiness[T any](hdl Handle[T], await func(context.Context) error) {
	if rr, ok := hdl.(readinessRegistrar); ok {
		rr.registerReadiness(await)
	}
}
