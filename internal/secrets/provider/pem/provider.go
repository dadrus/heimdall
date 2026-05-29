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
	"path/filepath"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/encoding"
	"github.com/dadrus/heimdall/internal/secrets/provider"
	"github.com/dadrus/heimdall/internal/secrets/registry"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

const ProviderType = "pem"

// by intention. Used only during application bootstrap.
//
//nolint:gochecknoinits
func init() {
	registry.Register(ProviderType, provider.FactoryFunc(newProvider))
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
	watch    bool

	watchMu      sync.Mutex
	started      bool
	resolvedPath string

	logger zerolog.Logger

	mu    sync.RWMutex
	store store

	observer provider.ChangeObserver

	watchStop context.CancelFunc
	watcherWg sync.WaitGroup
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

	logger.Info().Msg("Loading pem file")

	store, err := loadStore(cfg.Path, cfg.Password)
	if err != nil {
		return nil, err
	}

	return &pemProvider{
		path:     cfg.Path,
		password: cfg.Password,
		watch:    cfg.Watch,
		logger:   logger,
		observer: args.Observer,
		store:    store,
	}, nil
}

func (*pemProvider) Dependencies() []provider.Reference { return nil }
func (*pemProvider) IsNamespaceAware() bool             { return false }
func (*pemProvider) Type() string                       { return ProviderType }

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
	if !p.watch {
		return nil
	}

	p.watchMu.Lock()
	defer p.watchMu.Unlock()

	if p.started {
		return nil
	}

	resolvedPath, err := filepath.EvalSymlinks(p.path)
	if err != nil {
		return errorchain.NewWithMessagef(provider.ErrInternal,
			"failed to resolve pem provider watch path %s", p.path).CausedBy(err)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return errorchain.NewWithMessage(provider.ErrInternal,
			"failed to initialize fsnotify watcher for pem provider").CausedBy(err)
	}

	if err = watcher.Add(p.path); err != nil {
		_ = watcher.Close()

		return errorchain.NewWithMessagef(provider.ErrInternal,
			"failed to register pem provider watch for %s", p.path).CausedBy(err)
	}

	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))

	p.resolvedPath = resolvedPath
	p.watchStop = cancel
	p.started = true

	p.watcherWg.Add(1)

	go p.runWatcher(runCtx, watcher)

	return nil
}

func (p *pemProvider) Stop(_ context.Context) error {
	p.watchMu.Lock()

	cancel := p.watchStop
	started := p.started

	p.watchStop = nil
	p.started = false
	p.resolvedPath = ""

	p.watchMu.Unlock()

	if started && cancel != nil {
		cancel()
		p.watcherWg.Wait()
	}

	return nil
}

func (p *pemProvider) reload() {
	next, err := loadStore(p.path, p.password)
	if err != nil {
		p.logger.Warn().
			Err(err).
			Str("_file", p.path).
			Msg("Reloading pem file failed")

		return
	}

	p.mu.Lock()

	if !p.store.sameKind(next) {
		p.mu.Unlock()
		p.logger.Warn().
			Str("_file", p.path).
			Msg("Reloading pem file failed because store kind changed")

		return
	}

	p.store = next

	p.mu.Unlock()

	p.observer.Notify(provider.ChangeEvent{})

	p.logger.Info().
		Str("_file", p.path).
		Msg("pem file reloaded")
}

func (p *pemProvider) runWatcher(ctx context.Context, watcher *fsnotify.Watcher) {
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

			shouldReload := isReloadEvent(evt)

			if isAtomicUpdateEvent(evt) {
				shouldReload = shouldReload || p.updateWatchForAtomicUpdate(watcher, p.path)
			}

			if shouldReload {
				p.reload()
			}

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

func (p *pemProvider) updateWatchForAtomicUpdate(watcher *fsnotify.Watcher, path string) bool {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			_ = watcher.Remove(path)

			return false
		}

		p.logger.Warn().
			Err(err).
			Str("_file", path).
			Msg("Checking pem file for atomic update failed")

		return false
	}

	resolvedPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		p.logger.Warn().
			Err(err).
			Str("_file", path).
			Msg("Resolving pem file symlink target failed")

		return false
	}

	p.watchMu.Lock()
	defer p.watchMu.Unlock()

	if p.resolvedPath == resolvedPath {
		return false
	}

	_ = watcher.Remove(path)

	p.resolvedPath = resolvedPath

	if err = watcher.Add(path); err != nil {
		p.logger.Warn().
			Err(err).
			Str("_file", path).
			Msg("Re-registering pem file watch after atomic update failed")

		return false
	}

	return true
}

func isReloadEvent(evt fsnotify.Event) bool {
	return evt.Has(fsnotify.Write) ||
		evt.Has(fsnotify.Create) ||
		evt.Has(fsnotify.Rename)
}

func isAtomicUpdateEvent(evt fsnotify.Event) bool {
	return evt.Has(fsnotify.Chmod)
}

func loadStore(path, password string) (store, error) {
	data, err := readFile(path)
	if err != nil {
		return nil, err
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
