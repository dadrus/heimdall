package filesystem

import (
	"context"
	"os"
	"path/filepath"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/event"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type provider struct {
	src     string
	watcher *fsnotify.Watcher
	queue   event.RuleSetChangedEventQueue
	logger  zerolog.Logger
}

func newProvider(
	conf *config.FileBasedRuleProviderConfig,
	queue event.RuleSetChangedEventQueue,
	logger zerolog.Logger,
) (*provider, error) {
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
		src:     absPath,
		watcher: watcher,
		queue:   queue,
		logger:  logger,
	}, nil
}

func (p *provider) Start(ctx context.Context) error {
	p.logger.Info().
		Str("_rule_provider_type", "file_system").
		Msg("Starting rule definitions provider")

	if err := p.loadInitialRuleSet(); err != nil {
		return err
	}

	if p.watcher == nil {
		p.logger.Warn().
			Str("_rule_provider_type", "file_system").
			Msg("Watcher for file_system provider is not configured. Updates to rules will have no effects.")

		return nil
	}

	if err := p.watcher.Add(p.src); err != nil {
		p.logger.Error().Err(err).
			Str("_rule_provider_type", "file_system").
			Msg("Failed to start rule definitions provider")

		return err
	}

	go p.watchFiles()

	return nil
}

func (p *provider) watchFiles() {
	p.logger.Debug().
		Str("_rule_provider_type", "file_system").
		Msg("Watching rule files for changes")

	for {
		select {
		case event, ok := <-p.watcher.Events:
			if !ok {
				p.logger.Debug().
					Str("_rule_provider_type", "file_system").
					Msg("Watcher events channel closed")

				return
			}

			p.logger.Debug().
				Str("_rule_provider_type", "file_system").
				Str("_event", event.String()).
				Str("_src", event.Name).
				Msg("Rule update event received")

			switch {
			case event.Op&fsnotify.Create == fsnotify.Create:
				p.notifyRuleSetCreated(event)
			case event.Op&fsnotify.Remove == fsnotify.Remove:
				p.notifyRuleSetDeleted(event)
			case event.Op&fsnotify.Write == fsnotify.Write:
				p.notifyRuleSetDeleted(event)
				p.notifyRuleSetCreated(event)
			}
		case err, ok := <-p.watcher.Errors:
			if !ok {
				p.logger.Debug().
					Str("_rule_provider_type", "file_system").
					Msg("Watcher error channel closed")

				return
			}

			p.logger.Warn().Err(err).
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
		p.logger.Error().Err(err).
			Str("_rule_provider_type", "file_system").
			Str("_file", file).
			Msg("Failed reading")

		return
	}

	if len(data) == 0 {
		p.logger.Warn().
			Str("_rule_provider_type", "file_system").
			Str("_file", file).
			Msg("File is empty")

		return
	}

	p.ruleSetChanged(event.RuleSetChangedEvent{
		Src:        "file_system:" + file,
		Definition: data,
		ChangeType: event.Create,
	})
}

func (p *provider) Stop(ctx context.Context) error {
	p.logger.Info().
		Str("_rule_provider_type", "file_system").
		Msg("Tearing down rule provider")

	if p.watcher != nil {
		return p.watcher.Close()
	}

	return nil
}

func (p *provider) loadInitialRuleSet() error {
	p.logger.Info().
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
				p.logger.Warn().
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
			p.logger.Error().Err(err).
				Str("_rule_provider_type", "file_system").
				Msg("Failed loading initial rule set")

			return err
		}

		if len(data) == 0 {
			p.logger.Warn().
				Str("_rule_provider_type", "file_system").
				Str("_file", src).
				Msg("File is empty")

			continue
		}

		p.ruleSetChanged(event.RuleSetChangedEvent{
			Src:        "file_system:" + src,
			Definition: data,
			ChangeType: event.Create,
		})
	}

	return nil
}

func (p *provider) ruleSetChanged(evt event.RuleSetChangedEvent) {
	p.logger.Info().
		Str("_rule_provider_type", "file_system").
		Str("_src", evt.Src).
		Str("_type", evt.ChangeType.String()).
		Msg("Rule set changed")
	p.queue <- evt
}
