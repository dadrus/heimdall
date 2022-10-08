package filesystem

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/rules/event"
)

var ErrInvalidProviderConfiguration = errors.New("invalid provider configuration")

type fileSystemProvider struct {
	src     string
	watcher *fsnotify.Watcher
	queue   event.RuleSetChangedEventQueue
	logger  zerolog.Logger
}

func registerFileSystemProvider(
	lifecycle fx.Lifecycle,
	logger zerolog.Logger,
	conf config.Configuration,
	queue event.RuleSetChangedEventQueue,
) error {
	if conf.Rules.Providers.File == nil {
		logger.Debug().Msg("File based rule provider not configured. Skipping it.")

		return nil
	}

	provider, err := newFileSystemProvider(conf.Rules.Providers.File, queue, logger)
	if err != nil {
		logger.Error().Err(err).
			Str("_type", "file_system").Msg("Failed to load rule definitions provider.")

		return err
	}

	lifecycle.Append(
		fx.Hook{
			OnStart: func(ctx context.Context) error {
				return provider.Start()
			},
			OnStop: func(ctx context.Context) error {
				return provider.Stop()
			},
		},
	)

	return nil
}

func newFileSystemProvider(
	conf *config.FileBasedRuleProviderConfig,
	queue event.RuleSetChangedEventQueue,
	logger zerolog.Logger,
) (*fileSystemProvider, error) {
	if len(conf.Src) == 0 {
		return nil, ErrInvalidProviderConfiguration
	}

	absPath, err := filepath.Abs(conf.Src)
	if err != nil {
		return nil, err
	}

	_, err = os.Stat(absPath)
	if err != nil {
		return nil, err
	}

	var watcher *fsnotify.Watcher
	if conf.Watch {
		watcher, err = fsnotify.NewWatcher()
		if err != nil {
			return nil, err
		}
	}

	return &fileSystemProvider{
		src:     absPath,
		watcher: watcher,
		queue:   queue,
		logger:  logger,
	}, nil
}

func (p *fileSystemProvider) Start() error {
	p.logger.Info().Str("_type", "file_system").Msg("Starting rule definitions provider")

	if err := p.loadInitialRuleSet(); err != nil {
		return err
	}

	if p.watcher == nil {
		p.logger.Warn().
			Msg("Watcher for file_system provider is not configured. Updates to rules will have no effects.")

		return nil
	}

	if err := p.watcher.Add(p.src); err != nil {
		p.logger.Error().Err(err).Str("_type", "file_system").
			Msg("Failed to start rule definitions provider")

		return err
	}

	go p.watchFiles()

	return nil
}

func (p *fileSystemProvider) watchFiles() {
	p.logger.Debug().Msg("Watching rule files for changes")

	for {
		select {
		case event, ok := <-p.watcher.Events:
			if !ok {
				p.logger.Debug().Msg("Watcher events channel closed")

				return
			}

			p.logger.Debug().
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
				p.logger.Debug().Msg("Watcher error channel closed")

				return
			}

			p.logger.Warn().Err(err).Msg("Watcher error received")
		}
	}
}

func (p *fileSystemProvider) notifyRuleSetDeleted(evt fsnotify.Event) {
	p.ruleSetChanged(event.RuleSetChangedEvent{
		Src:        "file_system:" + evt.Name,
		ChangeType: event.Remove,
	})
}

func (p *fileSystemProvider) notifyRuleSetCreated(evt fsnotify.Event) {
	file := evt.Name

	data, err := os.ReadFile(file)
	if err != nil {
		p.logger.Error().Err(err).Str("_file", file).Msg("Failed reading")

		return
	}

	if len(data) == 0 {
		p.logger.Warn().Str("_file", file).Msg("File is empty")

		return
	}

	p.ruleSetChanged(event.RuleSetChangedEvent{
		Src:        "file_system:" + file,
		Definition: data,
		ChangeType: event.Create,
	})
}

func (p *fileSystemProvider) Stop() error {
	p.logger.Info().Msg("Tearing down rule definitions provider: file_system")

	if p.watcher != nil {
		return p.watcher.Close()
	}

	return nil
}

func (p *fileSystemProvider) loadInitialRuleSet() error {
	p.logger.Info().Msg("Loading initial rule set")

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
				p.logger.Warn().Str("_path", path).Msg("Ignoring directory")

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
			p.logger.Error().Err(err).Msg("Failed loading initial rule set")

			return err
		}

		if len(data) == 0 {
			p.logger.Warn().Str("_file", src).Msg("File is empty")

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

func (p *fileSystemProvider) ruleSetChanged(evt event.RuleSetChangedEvent) {
	p.logger.Info().Str("_src", evt.Src).Str("_type", evt.ChangeType.String()).Msg("Rule set changed")
	p.queue <- evt
}
