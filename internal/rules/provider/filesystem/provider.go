// Copyright 2022 Dimitrij Drus <dadrus@gmx.de>
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

package filesystem

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type provider struct {
	src        string
	w          *fsnotify.Watcher
	p          rule.SetProcessor
	l          zerolog.Logger
	states     sync.Map
	configured bool
}

func newProvider(conf *config.Configuration, processor rule.SetProcessor, logger zerolog.Logger) (*provider, error) {
	rawConf := conf.Rules.Providers.FileSystem

	if conf.Rules.Providers.FileSystem == nil {
		return &provider{}, nil
	}

	type Config struct {
		Src   string `koanf:"src"`
		Watch bool   `koanf:"watch"`
	}

	var providerConf Config
	if err := decodeConfig(rawConf, &providerConf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to decode file_system rule provider config").
			CausedBy(err)
	}

	if len(providerConf.Src) == 0 {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "no src configured for file_system rule provider")
	}

	absPath, err := filepath.Abs(providerConf.Src)
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to get the absolute path for the configured src").
			CausedBy(err)
	}

	_, err = os.Stat(absPath)
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal,
				"failed to get information about configured src form the file system").
			CausedBy(err)
	}

	var watcher *fsnotify.Watcher
	if providerConf.Watch {
		watcher, err = fsnotify.NewWatcher()
		if err != nil {
			return nil, errorchain.
				NewWithMessage(heimdall.ErrInternal, "failed to instantiating new file watcher").
				CausedBy(err)
		}
	}

	logger = logger.With().Str("_provider_type", "file_system").Logger()
	logger.Info().Msg("Rule provider configured.")

	return &provider{
		src:        absPath,
		w:          watcher,
		p:          processor,
		l:          logger,
		configured: true,
	}, nil
}

func (p *provider) Start(_ context.Context) error {
	if !p.configured {
		return nil
	}

	p.l.Info().Msg("Starting rule definitions provider")

	if err := p.loadInitialRuleSet(); err != nil {
		p.l.Error().Err(err).Msg("Failed loading initial rule sets")

		return err
	}

	if p.w == nil {
		p.l.Warn().
			Msg("Watcher for file_system provider is not configured. Updates to rules will have no effects.")

		return nil
	}

	if err := p.w.Add(p.src); err != nil {
		p.l.Error().Err(err).Msg("Failed to start rule definitions provider")

		return err
	}

	go p.watchFiles()

	return nil
}

func (p *provider) Stop(_ context.Context) error {
	if !p.configured {
		return nil
	}

	p.l.Info().Msg("Tearing down rule provider")

	if p.w != nil {
		return p.w.Close()
	}

	return nil
}

func (p *provider) watchFiles() {
	p.l.Debug().Msg("Watching rule files for changes")

	for {
		select {
		case evt, ok := <-p.w.Events:
			if !ok {
				p.l.Debug().Msg("Watcher events channel closed")

				return
			}

			p.ruleSetsChanged(evt)
		case err, ok := <-p.w.Errors:
			if !ok {
				p.l.Debug().Msg("Watcher error channel closed")

				return
			}

			p.l.Warn().Err(err).Msg("Watcher error received")
		}
	}
}

func (p *provider) ruleSetsChanged(evt fsnotify.Event) {
	p.l.Debug().
		Str("_event", evt.String()).
		Str("_src", evt.Name).
		Msg("Rule update event received")

	switch {
	case evt.Has(fsnotify.Create):
		ruleSet, err := p.loadRuleSet(evt.Name)
		if err != nil {
			p.l.Warn().Err(err).Msg("Failed to load rule set")

			return
		}

		p.states.Store(evt.Name, ruleSet.Hash)

		p.p.OnCreated(ruleSet)
	case evt.Has(fsnotify.Remove):
		p.states.Delete(evt.Name)
		p.p.OnDeleted(
			&rule.SetConfiguration{SetMeta: rule.SetMeta{Source: fmt.Sprintf("file_system:%s", evt.Name)}})
	case evt.Has(fsnotify.Write) || evt.Has(fsnotify.Chmod):
		ruleSet, err := p.loadRuleSet(evt.Name)
		if err != nil {
			if errors.Is(err, rule.ErrEmptyRuleSet) || errors.Is(err, os.ErrNotExist) {
				p.states.Delete(evt.Name)
				p.p.OnDeleted(
					&rule.SetConfiguration{SetMeta: rule.SetMeta{Source: fmt.Sprintf("file_system:%s", evt.Name)}})

				return
			}

			p.l.Warn().Err(err).Msg("Failed to load rule set")

			return
		}

		var hash []byte

		value, ok := p.states.Load(evt.Name)
		if ok {
			hash = value.([]byte) // nolint: forcetypeassert
		}

		p.states.Store(evt.Name, ruleSet.Hash)

		if len(hash) == 0 {
			p.p.OnCreated(ruleSet)
		} else {
			p.p.OnUpdated(ruleSet)
		}
	}
}

func (p *provider) loadRuleSet(fileName string) (*rule.SetConfiguration, error) {
	file, err := os.Open(fileName)
	if err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrInternal,
			"failed opening file %s", fileName).CausedBy(err)
	}

	md := sha256.New()

	ruleSet, err := rule.ParseRules("application/yaml", io.TeeReader(file, md))
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal, "failed to parse received rule set").
			CausedBy(err)
	}

	stat, _ := os.Stat(fileName)

	ruleSet.Hash = md.Sum(nil)
	ruleSet.Source = fmt.Sprintf("file_system:%s", fileName)
	ruleSet.ModTime = stat.ModTime()

	return ruleSet, nil
}

func (p *provider) loadInitialRuleSet() error {
	p.l.Info().Msg("Loading initial rule set")

	var sources []string

	fInfo, err := os.Stat(p.src)
	if err != nil {
		return err
	}

	if fInfo.IsDir() {
		dirEntries, err := os.ReadDir(p.src)
		if err != nil {
			return err
		}

		for _, entry := range dirEntries {
			path := filepath.Join(p.src, entry.Name())

			if entry.IsDir() {
				p.l.Warn().Str("_path", path).Msg("Ignoring directory")

				continue
			}

			sources = append(sources, path)
		}
	} else {
		sources = append(sources, p.src)
	}

	for _, src := range sources {
		ruleSet, err := p.loadRuleSet(src)
		if err != nil {
			if errors.Is(err, rule.ErrEmptyRuleSet) {
				continue
			}

			return err
		}

		p.p.OnCreated(ruleSet)
	}

	return nil
}
