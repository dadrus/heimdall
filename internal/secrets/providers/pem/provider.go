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
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/secrets/registry"
	"github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

const ProviderType = "pem"

// by intention. Used only during application bootstrap.
//
//nolint:gochecknoinits
func init() {
	registry.Register(ProviderType, registry.FactoryFunc(newProvider))
}

type provider struct {
	name     string
	path     string
	password string
	watch    bool
	watchMu  sync.Mutex
	started  bool
	logger   zerolog.Logger

	mu sync.RWMutex
	ks keyStore

	watchStop context.CancelFunc
	watcherWg sync.WaitGroup
}

func newProvider(appCtx app.Context, sourceName string, rawConf map[string]any) (types.Provider, error) {
	type config struct {
		Path     string `mapstructure:"path"     validate:"required"`
		Password string `mapstructure:"password"`
		Watch    bool   `mapstructure:"watch"`
	}

	var cfg config

	if err := decodeConfig(appCtx.Validator(), rawConf, &cfg); err != nil {
		return nil, err
	}

	ks, err := newKeyStoreFromPEMFile(sourceName, cfg.Path, cfg.Password)
	if err != nil {
		return nil, err
	}

	return &provider{
		name:     sourceName,
		path:     cfg.Path,
		password: cfg.Password,
		watch:    cfg.Watch,
		ks:       ks,
		logger:   appCtx.Logger(),
	}, nil
}

func (p *provider) Name() string { return p.name }

func (p *provider) Type() string { return ProviderType }

func (p *provider) ResolveSecret(_ context.Context, selector types.Selector) (types.Secret, error) {
	p.mu.RLock()
	ks := p.ks
	p.mu.RUnlock()

	if len(ks) == 0 {
		return nil, types.ErrSecretNotFound
	}

	if selector.Value != "" {
		return ks.get(selector.Value)
	}

	return ks[0], nil
}

func (p *provider) ResolveSecretSet(_ context.Context, _ types.Selector) ([]types.Secret, error) {
	p.mu.RLock()
	ks := p.ks
	p.mu.RUnlock()

	return ks, nil
}

func (p *provider) ResolveCredentials(_ context.Context, _ types.Selector) (types.Credentials, error) {
	return nil, types.ErrUnsupportedOperation
}

func (p *provider) Start(ctx context.Context, onChange func(types.ChangeEvent)) error {
	if !p.watch {
		return nil
	}

	if onChange == nil {
		return errorchain.NewWithMessage(pipeline.ErrInternal, "onChange callback must not be nil")
	}

	p.watchMu.Lock()
	defer p.watchMu.Unlock()

	if p.started {
		return nil
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return errorchain.NewWithMessage(pipeline.ErrInternal,
			"failed to initialize fsnotify watcher for pem provider").CausedBy(err)
	}

	if err = watcher.Add(p.path); err != nil {
		_ = watcher.Close()

		return errorchain.NewWithMessagef(pipeline.ErrInternal,
			"failed to register pem provider watch for %s", p.path).CausedBy(err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	p.watchStop = cancel
	p.started = true
	p.watcherWg.Add(1)

	go p.runWatcher(runCtx, watcher, onChange)

	return nil
}

func (p *provider) Stop(_ context.Context) error {
	p.watchMu.Lock()
	cancel := p.watchStop
	started := p.started
	p.watchStop = nil
	p.started = false
	p.watchMu.Unlock()

	if started && cancel != nil {
		cancel()
		p.watcherWg.Wait()
	}

	return nil
}

func (p *provider) reload() error {
	ks, err := newKeyStoreFromPEMFile(p.name, p.path, p.password)
	if err != nil {
		return err
	}

	p.mu.Lock()
	p.ks = ks
	p.mu.Unlock()

	return nil
}

func (p *provider) runWatcher(ctx context.Context, watcher *fsnotify.Watcher, onChange func(types.ChangeEvent)) {
	defer p.watcherWg.Done()
	defer func() {
		_ = watcher.Close()
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-watcher.Events:
			if !ok {
				return
			}

			if !isReloadEvent(evt) {
				continue
			}

			if err := p.reload(); err != nil {
				p.logger.Warn().
					Err(err).
					Str("_source", p.name).
					Str("_file", p.path).
					Msg("Reloading pem source failed")

				continue
			}

			onChange(types.ChangeEvent{Source: p.name})

			p.logger.Info().
				Str("_source", p.name).
				Str("_file", p.path).
				Msg("PEM source reloaded")
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}

			p.logger.Warn().
				Err(err).
				Str("_source", p.name).
				Str("_file", p.path).
				Msg("PEM source watcher error")
		}
	}
}

func isReloadEvent(evt fsnotify.Event) bool {
	return evt.Has(fsnotify.Write) ||
		evt.Has(fsnotify.Create) ||
		evt.Has(fsnotify.Rename) ||
		evt.Has(fsnotify.Chmod)
}
