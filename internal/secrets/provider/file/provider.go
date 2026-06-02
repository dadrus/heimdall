// Copyright 2026 Dimitrij Drus
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package file

import (
	"context"
	"os"
	"sync"

	"github.com/rs/zerolog"
	"gopkg.in/yaml.v3"

	"github.com/dadrus/heimdall/internal/encoding"
	"github.com/dadrus/heimdall/internal/secrets/provider"
	"github.com/dadrus/heimdall/internal/secrets/registry"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/fswatch"
)

const providerType = "file"

// by intention. Used only during application bootstrap.
//
//nolint:gochecknoinits
func init() {
	registry.Register(providerType, provider.FactoryFunc(newProvider))
}

type fileProvider struct {
	file     string
	logger   zerolog.Logger
	observer provider.ChangeObserver

	mu          sync.RWMutex
	secrets     map[string]provider.Secret
	credentials map[string]provider.Credentials

	watcher *fswatch.Watcher
}

func newProvider(args provider.Args) (provider.Provider, error) {
	type config struct {
		Path  string `mapstructure:"path"  validate:"required"`
		Watch bool   `mapstructure:"watch"`
	}

	var cfg config

	dec := args.DecoderFactory.Decoder(encoding.WithTagName("mapstructure"))
	if err := dec.DecodeMap(&cfg, args.Config); err != nil {
		return nil, err
	}

	prv := &fileProvider{
		file:        cfg.Path,
		logger:      args.Logger,
		observer:    args.Observer,
		secrets:     make(map[string]provider.Secret),
		credentials: make(map[string]provider.Credentials),
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
			"failed to initialize file provider watcher",
		).CausedBy(err)
	}

	prv.watcher = watcher

	return prv, nil
}

func (*fileProvider) Dependencies() []provider.Reference { return nil }
func (*fileProvider) IsNamespaceAware() bool             { return false }
func (*fileProvider) Type() string                       { return providerType }

func (p *fileProvider) Start(ctx context.Context) error {
	p.logger.Info().
		Str("_file", p.file).
		Msg("Loading secrets")

	secrets, credentials, err := loadFile(p.file)
	if err != nil {
		return err
	}

	p.mu.Lock()
	p.secrets = secrets
	p.credentials = credentials
	p.mu.Unlock()

	if p.watcher == nil {
		return nil
	}

	if err = p.watcher.Add(p.file); err != nil {
		return errorchain.NewWithMessagef(
			provider.ErrInternal,
			"failed to register file provider watch for %s", p.file,
		).CausedBy(err)
	}

	if err = p.watcher.Start(context.WithoutCancel(ctx)); err != nil {
		return errorchain.NewWithMessagef(
			provider.ErrInternal,
			"failed to start file provider watch for %s", p.file,
		).CausedBy(err)
	}

	return nil
}

func (p *fileProvider) Stop(ctx context.Context) error {
	if p.watcher == nil {
		return nil
	}

	watcher := p.watcher
	p.watcher = nil

	return watcher.Stop(ctx)
}

func (p *fileProvider) GetSecret(
	_ context.Context,
	selector provider.Selector,
) (provider.Secret, error) {
	p.mu.RLock()
	secret := p.secrets[selector.Value]
	p.mu.RUnlock()

	if secret == nil {
		return nil, errorchain.NewWithMessagef(
			provider.ErrSecretNotFound, "selector '%s'", selector.Value,
		)
	}

	return secret, nil
}

func (p *fileProvider) GetSecretSet(
	_ context.Context,
	_ provider.Selector,
) ([]provider.Secret, error) {
	return nil, provider.ErrUnsupportedOperation
}

func (p *fileProvider) GetCredentials(
	_ context.Context,
	selector provider.Selector,
) (provider.Credentials, error) {
	p.mu.RLock()
	credentials := p.credentials[selector.Value]
	p.mu.RUnlock()

	if credentials == nil {
		return nil, errorchain.NewWithMessagef(
			provider.ErrCredentialsNotFound, "selector '%s'", selector.Value,
		)
	}

	return credentials, nil
}

func (p *fileProvider) GetCertificateBundle(
	_ context.Context,
	_ provider.Selector,
) (provider.CertificateBundle, error) {
	return nil, provider.ErrUnsupportedOperation
}

func (p *fileProvider) reload(evt fswatch.Event) error {
	if evt.Op != fswatch.OpChanged {
		return nil
	}

	secrets, credentials, err := loadFile(p.file)
	if err != nil {
		return err
	}

	p.mu.Lock()
	p.secrets = secrets
	p.credentials = credentials
	p.mu.Unlock()

	p.logger.Info().Str("_file", p.file).Msg("Secrets file reloaded")
	p.observer.Notify(provider.ChangeEvent{})

	return nil
}

func loadFile(path string) (map[string]provider.Secret, map[string]provider.Credentials, error) {
	reader, err := os.Open(path)
	if err != nil {
		return nil, nil, errorchain.NewWithMessagef(
			provider.ErrConfiguration,
			"failed opening secrets file %s", path,
		).CausedBy(err)
	}

	defer func() { _ = reader.Close() }()

	var raw map[string]any
	if err = yaml.NewDecoder(reader).Decode(&raw); err != nil {
		return nil, nil, errorchain.NewWithMessagef(
			provider.ErrConfiguration,
			"failed parsing secrets file %s", path,
		).CausedBy(err)
	}

	return newEntries(raw)
}

func newEntries(raw map[string]any) (map[string]provider.Secret, map[string]provider.Credentials, error) {
	secrets := make(map[string]provider.Secret, len(raw))
	credentials := make(map[string]provider.Credentials, len(raw))

	for key, value := range raw {
		switch typed := value.(type) {
		case string:
			secrets[key] = provider.NewStringSecret(key, typed)
		case map[string]any:
			credentials[key] = provider.NewCredentials(key, typed)
		default:
			return nil, nil, errorchain.NewWithMessagef(
				provider.ErrConfiguration,
				"file secret '%s' must be either string or structured object", key,
			)
		}
	}

	return secrets, credentials, nil
}
