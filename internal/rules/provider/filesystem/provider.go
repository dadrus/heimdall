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
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	config2 "github.com/dadrus/heimdall/internal/rules/config"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type Provider struct {
	src            string
	w              *fsnotify.Watcher
	p              rule.SetProcessor
	l              zerolog.Logger
	states         sync.Map
	envVarsEnabled bool
	configured     bool
}

func NewProvider(conf *config.Configuration, processor rule.SetProcessor, logger zerolog.Logger) (*Provider, error) {
	rawConf := conf.Providers.FileSystem

	if conf.Providers.FileSystem == nil {
		return &Provider{}, nil
	}

	type Config struct {
		Src            string `mapstructure:"src"`
		Watch          bool   `mapstructure:"watch"`
		EnvVarsEnabled bool   `mapstructure:"env_vars_enabled"`
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

	return &Provider{
		src:            absPath,
		w:              watcher,
		p:              processor,
		l:              logger,
		configured:     true,
		envVarsEnabled: providerConf.EnvVarsEnabled,
	}, nil
}

func (p *Provider) Start(_ context.Context) error {
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

func (p *Provider) Stop(_ context.Context) error {
	if !p.configured {
		return nil
	}

	p.l.Info().Msg("Tearing down rule provider")

	if p.w != nil {
		return p.w.Close()
	}

	return nil
}

func (p *Provider) watchFiles() {
	p.l.Debug().Msg("Watching rule files for changes")

	for {
		select {
		case evt, ok := <-p.w.Events:
			if !ok {
				p.l.Debug().Msg("Watcher closed")

				return
			}

			if err := p.ruleSetsChanged(evt); err != nil {
				p.l.Warn().Err(err).Str("_src", evt.Name).Msg("Failed to apply rule set changes")
			}
		case err, ok := <-p.w.Errors:
			if !ok {
				p.l.Debug().Msg("Watcher error channel closed")

				return
			}

			p.l.Warn().Err(err).Msg("Watcher error received")
		}
	}
}

func (p *Provider) ruleSetsChanged(evt fsnotify.Event) error {
	p.l.Debug().
		Str("_event", evt.String()).
		Str("_src", evt.Name).
		Msg("Rule update event received")

	var err error

	switch {
	case evt.Has(fsnotify.Create) || evt.Has(fsnotify.Write) || evt.Has(fsnotify.Chmod):
		err = p.ruleSetCreatedOrUpdated(evt.Name)
	case evt.Has(fsnotify.Remove):
		err = p.ruleSetDeleted(evt.Name)
	}

	return err
}

func (p *Provider) ruleSetCreatedOrUpdated(fileName string) error {
	ruleSet, err := p.loadRuleSet(fileName)
	if err != nil {
		if errors.Is(err, config2.ErrEmptyRuleSet) || errors.Is(err, os.ErrNotExist) {
			return p.ruleSetDeleted(fileName)
		}

		return err
	}

	var hash []byte

	value, ok := p.states.Load(fileName)
	if ok {
		hash = value.([]byte) // nolint: forcetypeassert
	}

	switch {
	case len(hash) == 0:
		err = p.p.OnCreated(ruleSet)
	case !bytes.Equal(hash, ruleSet.Hash):
		err = p.p.OnUpdated(ruleSet)
	default:
		return nil
	}

	if err != nil {
		return err
	}

	p.states.Store(fileName, ruleSet.Hash)

	return nil
}

func (p *Provider) ruleSetDeleted(fileName string) error {
	if _, ok := p.states.Load(fileName); !ok {
		return nil
	}

	conf := &config2.RuleSet{
		MetaData: config2.MetaData{
			Source:  fmt.Sprintf("file_system:%s", fileName),
			ModTime: time.Now(),
		},
	}

	if err := p.p.OnDeleted(conf); err != nil {
		return err
	}

	p.states.Delete(fileName)

	return nil
}

func (p *Provider) loadRuleSet(fileName string) (*config2.RuleSet, error) {
	file, err := os.Open(fileName)
	if err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrInternal,
			"failed opening file %s", fileName).CausedBy(err)
	}

	md := sha256.New()

	ruleSet, err := config2.ParseRules("application/yaml", io.TeeReader(file, md), p.envVarsEnabled)
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

func (p *Provider) loadInitialRuleSet() error {
	p.l.Info().Msg("Loading initial rule set")

	sources, err := p.sources()
	if err != nil {
		return err
	}

	for _, src := range sources {
		if err = p.ruleSetCreatedOrUpdated(src); err != nil {
			return err
		}
	}

	return nil
}

func (p *Provider) sources() ([]string, error) {
	var sources []string

	fInfo, err := os.Stat(p.src)
	if err != nil {
		return nil, err
	}

	if fInfo.IsDir() {
		dirEntries, err := os.ReadDir(p.src)
		if err != nil {
			return nil, err
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

	return sources, nil
}
