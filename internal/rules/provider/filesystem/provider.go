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
	"fmt"
	"os"
	"path/filepath"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/event"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type provider struct {
	src string
	w   *fsnotify.Watcher
	q   event.RuleSetChangedEventQueue
	l   zerolog.Logger
}

func newProvider(
	rawConf map[string]any,
	queue event.RuleSetChangedEventQueue,
	logger zerolog.Logger,
) (*provider, error) {
	type Config struct {
		Src   string `koanf:"src"`
		Watch bool   `koanf:"watch"`
	}

	var conf Config
	if err := decodeConfig(rawConf, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to decode file_system rule provider config").
			CausedBy(err)
	}

	if len(conf.Src) == 0 {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "no src configured for file_system rule provider")
	}

	absPath, err := filepath.Abs(conf.Src)
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
	if conf.Watch {
		watcher, err = fsnotify.NewWatcher()
		if err != nil {
			return nil, errorchain.
				NewWithMessage(heimdall.ErrInternal, "failed to instantiating new file watcher").
				CausedBy(err)
		}
	}

	return &provider{
		src: absPath,
		w:   watcher,
		q:   queue,
		l:   logger,
	}, nil
}

func (p *provider) Start(_ context.Context) error {
	p.l.Info().
		Str("_rule_provider_type", "file_system").
		Msg("Starting rule definitions provider")

	if err := p.loadInitialRuleSet(); err != nil {
		p.l.Error().Err(err).
			Str("_rule_provider_type", "file_system").
			Msg("Failed loading initial rule sets")

		return err
	}

	if p.w == nil {
		p.l.Warn().
			Str("_rule_provider_type", "file_system").
			Msg("Watcher for file_system provider is not configured. Updates to rules will have no effects.")

		return nil
	}

	if err := p.w.Add(p.src); err != nil {
		p.l.Error().Err(err).
			Str("_rule_provider_type", "file_system").
			Msg("Failed to start rule definitions provider")

		return err
	}

	go p.watchFiles()

	return nil
}

func (p *provider) Stop(_ context.Context) error {
	p.l.Info().
		Str("_rule_provider_type", "file_system").
		Msg("Tearing down rule provider")

	if p.w != nil {
		return p.w.Close()
	}

	return nil
}

func (p *provider) watchFiles() {
	p.l.Debug().
		Str("_rule_provider_type", "file_system").
		Msg("Watching rule files for changes")

	for {
		select {
		case evt, ok := <-p.w.Events:
			if !ok {
				p.l.Debug().
					Str("_rule_provider_type", "file_system").
					Msg("Watcher events channel closed")

				return
			}

			p.l.Debug().
				Str("_rule_provider_type", "file_system").
				Str("_event", evt.String()).
				Str("_src", evt.Name).
				Msg("Rule update event received")

			switch {
			case evt.Op&fsnotify.Create == fsnotify.Create:
				p.notifyRuleSetCreated(evt)
			case evt.Op&fsnotify.Remove == fsnotify.Remove:
				p.notifyRuleSetDeleted(evt)
			case evt.Op&fsnotify.Write == fsnotify.Write:
				p.notifyRuleSetDeleted(evt)
				p.notifyRuleSetCreated(evt)
			}
		case err, ok := <-p.w.Errors:
			if !ok {
				p.l.Debug().
					Str("_rule_provider_type", "file_system").
					Msg("Watcher error channel closed")

				return
			}

			p.l.Warn().Err(err).
				Str("_rule_provider_type", "file_system").
				Msg("Watcher error received")
		}
	}
}

func (p *provider) notifyRuleSetDeleted(evt fsnotify.Event) {
	p.ruleSetChanged(event.RuleSetChangedEvent{
		Src:        "file_system:" + evt.Name,
		ChangeType: event.Remove,
	})
}

func (p *provider) notifyRuleSetCreated(evt fsnotify.Event) {
	file := evt.Name

	data, err := os.ReadFile(file)
	if err != nil {
		p.l.Error().Err(err).
			Str("_rule_provider_type", "file_system").
			Str("_file", file).
			Msg("Failed reading")

		return
	}

	if len(data) == 0 {
		p.l.Warn().
			Str("_rule_provider_type", "file_system").
			Str("_file", file).
			Msg("File is empty")

		return
	}

	ruleSet, err := rule.ParseRules("application/yaml", bytes.NewBuffer(data))
	if err != nil {
		p.l.Warn().
			Err(err).
			Str("_rule_provider_type", "file_system").
			Str("_file", file).
			Msg("Failed to parse rule set definition")

		return
	}

	p.ruleSetChanged(event.RuleSetChangedEvent{
		Src:        fmt.Sprintf("file_system:%s:%s", file, ruleSet.Name),
		RuleSet:    ruleSet.Rules,
		ChangeType: event.Create,
	})
}

func (p *provider) loadInitialRuleSet() error {
	p.l.Info().
		Str("_rule_provider_type", "file_system").
		Msg("Loading initial rule set")

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
				p.l.Warn().
					Str("_rule_provider_type", "file_system").
					Str("_path", path).
					Msg("Ignoring directory")

				continue
			}

			sources = append(sources, path)
		}
	} else {
		sources = append(sources, p.src)
	}

	for _, src := range sources {
		data, err := os.ReadFile(src)
		if err != nil {
			p.l.Error().Err(err).
				Str("_rule_provider_type", "file_system").
				Msg("Failed loading initial rule set")

			return err
		}

		if len(data) == 0 {
			p.l.Warn().
				Str("_rule_provider_type", "file_system").
				Str("_file", src).
				Msg("File is empty")

			return err
		}

		ruleSet, err := rule.ParseRules("application/yaml", bytes.NewBuffer(data))
		if err != nil {
			p.l.Warn().
				Err(err).
				Str("_rule_provider_type", "file_system").
				Str("_file", src).
				Msg("Failed to parse rule set definition")

			return err
		}

		p.ruleSetChanged(event.RuleSetChangedEvent{
			Src:        fmt.Sprintf("%s:%s:%s", "file_system", src, ruleSet.Name),
			RuleSet:    ruleSet.Rules,
			ChangeType: event.Create,
		})
	}

	return nil
}

func (p *provider) ruleSetChanged(evt event.RuleSetChangedEvent) {
	p.l.Info().
		Str("_rule_provider_type", "file_system").
		Str("_src", evt.Src).
		Str("_type", evt.ChangeType.String()).
		Msg("Rule set changed")
	p.q <- evt
}
