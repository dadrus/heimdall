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

	"github.com/dadrus/heimdall/internal/encoding"
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
	registry.Register(ProviderType, types.ProviderFactoryFunc(newProvider))
}

type provider struct {
	path     string
	password string
	watch    bool
	watchMu  sync.Mutex
	started  bool
	logger   zerolog.Logger

	mu sync.RWMutex
	ks keyStore

	observer  types.ChangeObserver
	watchStop context.CancelFunc
	watcherWg sync.WaitGroup
}

func newProvider(args types.ProviderArgs) (types.Provider, error) {
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

	ks, err := newKeyStoreFromPEMFile(cfg.Path, cfg.Password)
	if err != nil {
		return nil, err
	}

	return &provider{
		path:     cfg.Path,
		password: cfg.Password,
		watch:    cfg.Watch,
		logger:   args.Logger,
		observer: args.Observer,
		ks:       ks,
	}, nil
}

func (p *provider) Dependencies() []types.Reference { return nil }
func (p *provider) Type() string { return ProviderType }

func (p *provider) GetSecret(_ context.Context, selector types.Selector) (types.Secret, error) {
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

func (p *provider) GetSecretSet(_ context.Context, _ types.Selector) ([]types.Secret, error) {
	p.mu.RLock()
	ks := p.ks
	p.mu.RUnlock()

	return ks, nil
}

func (p *provider) GetCredentials(_ context.Context, _ types.Selector) (types.Credentials, error) {
	return nil, types.ErrUnsupportedOperation
}

func (p *provider) Start(ctx context.Context) error {
	if !p.watch {
		return nil
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

	go p.runWatcher(runCtx, watcher)

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
	ks, err := newKeyStoreFromPEMFile(p.path, p.password)
	if err != nil {
		return err
	}

	p.mu.Lock()
	p.ks = ks
	p.mu.Unlock()

	return nil
}

func (p *provider) runWatcher(ctx context.Context, watcher *fsnotify.Watcher) {
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
					Str("_file", p.path).
					Msg("Reloading pem file failed")

				continue
			}

			p.observer.Notify(types.ChangeEvent{})

			p.logger.Info().
				Str("_file", p.path).
				Msg("pem file reloaded")
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}

			p.logger.Warn().
				Err(err).
				Str("_file", p.path).
				Msg("pem file watching error")
		}
	}
}

func isReloadEvent(evt fsnotify.Event) bool {
	return evt.Has(fsnotify.Write) ||
		evt.Has(fsnotify.Create) ||
		evt.Has(fsnotify.Rename) ||
		evt.Has(fsnotify.Chmod)
}
