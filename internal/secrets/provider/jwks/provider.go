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

package jwks

import (
	"context"
	"sync"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/encoding"
	"github.com/dadrus/heimdall/internal/secrets/provider"
	"github.com/dadrus/heimdall/internal/secrets/registry"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/fswatch"
)

const providerType = "jwks"

// by intention. Used only during application bootstrap.
//
//nolint:gochecknoinits
func init() {
	registry.Register(providerType, provider.FactoryFunc(newProvider))
}

type jwksProvider struct {
	path     string
	observer provider.ChangeObserver
	watcher  *fswatch.Watcher
	logger   zerolog.Logger

	mu    sync.RWMutex
	store store
}

func newProvider(args provider.Args) (provider.Provider, error) {
	type config struct {
		Path  string `mapstructure:"path" validate:"required"`
		Watch bool   `mapstructure:"watch"`
	}

	var cfg config

	dec := args.DecoderFactory.Decoder(encoding.WithTagName("mapstructure"))
	if err := dec.DecodeMap(&cfg, args.Config); err != nil {
		return nil, err
	}

	prv := &jwksProvider{
		path:     cfg.Path,
		logger:   args.Logger,
		observer: args.Observer,
	}

	if !cfg.Watch {
		return prv, nil
	}

	watcher, err := fswatch.New(
		fswatch.EventHandlerFunc(prv.reload),
		fswatch.WithLogger(args.Logger),
	)
	if err != nil {
		return nil, errorchain.NewWithMessage(
			provider.ErrInternal,
			"failed to initialize jwks provider watcher",
		).CausedBy(err)
	}

	prv.watcher = watcher

	return prv, nil
}

func (*jwksProvider) Dependencies() []provider.Reference { return nil }
func (*jwksProvider) IsNamespaceAware() bool             { return false }
func (*jwksProvider) Type() string                       { return providerType }

func (p *jwksProvider) GetSecret(
	ctx context.Context,
	selector provider.Selector,
) (provider.Secret, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.store.getSecret(ctx, selector)
}

func (p *jwksProvider) GetSecretSet(
	ctx context.Context,
	selector provider.Selector,
) ([]provider.Secret, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.store.getSecretSet(ctx, selector)
}

func (p *jwksProvider) GetCredentials(
	_ context.Context,
	_ provider.Selector,
) (provider.Credentials, error) {
	return nil, provider.ErrUnsupportedOperation
}

func (p *jwksProvider) GetCertificateBundle(
	ctx context.Context,
	selector provider.Selector,
) (provider.CertificateBundle, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.store.getCertificateBundle(ctx, selector)
}

func (p *jwksProvider) Start(ctx context.Context) error {
	p.logger.Info().Str("_file", p.path).Msg("Loading jwks file")

	store, err := loadStore(p.path)
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
			"failed to register jwks provider watch for %s", p.path,
		).CausedBy(err)
	}

	if err = p.watcher.Start(context.WithoutCancel(ctx)); err != nil {
		return errorchain.NewWithMessagef(
			provider.ErrInternal,
			"failed to start jwks provider watch for %s", p.path,
		).CausedBy(err)
	}

	return nil
}

func (p *jwksProvider) Stop(ctx context.Context) error {
	if p.watcher == nil {
		return nil
	}

	watcher := p.watcher
	p.watcher = nil

	return watcher.Stop(ctx)
}

func (p *jwksProvider) reload(evt fswatch.Event) error {
	if evt.Op != fswatch.OpChanged {
		return nil
	}

	next, err := loadStore(p.path)
	if err != nil {
		return err
	}

	p.mu.Lock()

	if !p.store.sameKind(next) {
		p.mu.Unlock()

		return errorchain.NewWithMessage(
			provider.ErrConfiguration,
			"Reloading jwks file failed because store kind changed",
		)
	}

	p.store = next

	p.mu.Unlock()

	p.logger.Info().Str("_file", p.path).Msg("jwks file reloaded")
	p.observer.Notify(provider.ChangeEvent{})

	return nil
}
