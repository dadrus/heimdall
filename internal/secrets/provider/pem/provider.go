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

package pem

import (
	"context"
	"errors"
	"os"
	"sync"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/encoding"
	"github.com/dadrus/heimdall/internal/secrets/provider"
	"github.com/dadrus/heimdall/internal/secrets/registry"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/fswatch"
)

const providerType = "pem"

// by intention. Used only during application bootstrap.
//
//nolint:gochecknoinits
func init() {
	registry.Register(providerType, provider.FactoryFunc(newProvider))
}

type store interface {
	getSecret(ctx context.Context, selector provider.Selector) (provider.Secret, error)
	getSecretSet(ctx context.Context, selector provider.Selector) ([]provider.Secret, error)
	getCertificateBundle(ctx context.Context, selector provider.Selector) (provider.CertificateBundle, error)

	sameKind(other store) bool
}

type pemProvider struct {
	path     string
	password string

	observer provider.ChangeObserver
	watcher  *fswatch.Watcher
	logger   zerolog.Logger

	mu    sync.RWMutex
	store store
}

func newProvider(args provider.Args) (provider.Provider, error) {
	logger := args.Logger

	type config struct {
		Path     string `mapstructure:"path"     validate:"required"`
		Password string `mapstructure:"password"`
		Watch    bool   `mapstructure:"watch"`
	}

	var cfg config

	dec := args.DecoderFactory.Decoder(encoding.WithTagName("mapstructure"))
	if err := dec.DecodeMap(&cfg, args.Config); err != nil {
		return nil, err
	}

	prv := &pemProvider{
		path:     cfg.Path,
		password: cfg.Password,
		logger:   logger,
		observer: args.Observer,
	}

	if !cfg.Watch {
		return prv, nil
	}

	watcher, err := fswatch.New(
		fswatch.EventHandlerFunc(prv.reload),
		fswatch.WithLogger(logger),
	)
	if err != nil {
		return nil, errorchain.NewWithMessage(
			provider.ErrInternal,
			"failed to initialize pem provider watcher",
		).CausedBy(err)
	}

	prv.watcher = watcher

	return prv, nil
}

func (*pemProvider) Dependencies() []provider.Reference { return nil }
func (*pemProvider) IsNamespaceAware() bool             { return false }
func (*pemProvider) Type() string                       { return providerType }

func (p *pemProvider) GetSecret(
	ctx context.Context,
	selector provider.Selector,
) (provider.Secret, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.store.getSecret(ctx, selector)
}

func (p *pemProvider) GetSecretSet(
	ctx context.Context,
	selector provider.Selector,
) ([]provider.Secret, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.store.getSecretSet(ctx, selector)
}

func (p *pemProvider) GetCredentials(
	_ context.Context,
	_ provider.Selector,
) (provider.Credentials, error) {
	return nil, provider.ErrUnsupportedOperation
}

func (p *pemProvider) GetCertificateBundle(
	ctx context.Context,
	selector provider.Selector,
) (provider.CertificateBundle, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.store.getCertificateBundle(ctx, selector)
}

func (p *pemProvider) Start(ctx context.Context) error {
	p.logger.Info().
		Str("_file", p.path).
		Msg("Loading pem file")

	store, err := loadStore(p.path, p.password)
	if err != nil {
		return err
	}

	p.mu.Lock()
	p.store = store
	p.mu.Unlock()

	if p.watcher == nil {
		return nil
	}

	if err = p.watcher.Add(p.path); err != nil {
		return errorchain.NewWithMessagef(
			provider.ErrInternal,
			"failed to register pem provider watch for %s", p.path,
		).CausedBy(err)
	}

	if err = p.watcher.Start(context.WithoutCancel(ctx)); err != nil {
		return errorchain.NewWithMessagef(
			provider.ErrInternal,
			"failed to start pem provider watch for %s", p.path,
		).CausedBy(err)
	}

	return nil
}

func (p *pemProvider) Stop(ctx context.Context) error {
	if p.watcher == nil {
		return nil
	}

	watcher := p.watcher
	p.watcher = nil

	return watcher.Stop(ctx)
}

func (p *pemProvider) reload(evt fswatch.Event) error {
	if evt.Op != fswatch.OpChanged {
		return nil
	}

	next, err := loadStore(p.path, p.password)
	if err != nil {
		return err
	}

	p.mu.Lock()

	if !p.store.sameKind(next) {
		p.mu.Unlock()

		return errorchain.NewWithMessage(
			provider.ErrConfiguration,
			"Reloading pem file failed because store kind changed",
		)
	}

	p.store = next

	p.mu.Unlock()

	p.logger.Info().
		Str("_file", p.path).
		Msg("pem file reloaded")

	p.observer.Notify(provider.ChangeEvent{})

	return nil
}

func loadStore(path, password string) (store, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errorchain.NewWithMessagef(provider.ErrConfiguration,
			"failed to read pem file %s", path).CausedBy(err)
	}

	ks, err := newKeyStoreFromPEMBytes(data, password)
	if err == nil {
		return ks, nil
	}

	cs, bundleErr := newCertificateStoreFromPEMBytes(data)
	if bundleErr == nil {
		return cs, nil
	}

	if errors.Is(err, errNoKeyMaterialPresent) {
		return nil, bundleErr
	}

	return nil, err
}
