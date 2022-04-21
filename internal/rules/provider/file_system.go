package provider

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
)

var ErrInvalidProviderConfiguration = errors.New("invalid provider configuration")

type fileSystemProvider struct {
	src     string
	watcher *fsnotify.Watcher
	queue   RuleSetChangedEventQueue
	logger  zerolog.Logger
}

func registerFileSystemProvider(
	lifecycle fx.Lifecycle,
	logger zerolog.Logger,
	c config.Configuration,
	queue RuleSetChangedEventQueue,
) {
	provider, err := newFileSystemProvider(c, queue, logger)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to load rule definitions provider: file_system")

		return
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
}

func newFileSystemProvider(
	conf config.Configuration,
	queue RuleSetChangedEventQueue,
	logger zerolog.Logger,
) (*fileSystemProvider, error) {
	if len(conf.Rules.Providers.File.Src) == 0 {
		return nil, ErrInvalidProviderConfiguration
	}

	absPath, err := filepath.Abs(conf.Rules.Providers.File.Src)
	if err != nil {
		return nil, err
	}

	_, err = os.Stat(absPath)
	if err != nil {
		return nil, err
	}

	var watcher *fsnotify.Watcher
	if conf.Rules.Providers.File.Watch {
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
	p.logger.Info().Msg("Starting rule definitions provider: file_system")

	if err := p.loadInitialRuleSet(); err != nil {
		return err
	}

	if p.watcher == nil {
		p.logger.Warn().Msg("Watcher for file_system provider is not configured. Updates to rules will have no effects.")

		return nil
	}

	if err := p.watcher.Add(p.src); err != nil {
		p.logger.Error().Err(err).Msg("Failed to start rule definitions provider: file_system")

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
				Str("event", event.String()).
				Str("src", event.Name).
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

func (p *fileSystemProvider) getFilePath(event fsnotify.Event) string {
	if strings.HasSuffix(p.src, event.Name) {
		return p.src
	}

	// rule sets are in a directory
	return filepath.Join(p.src, event.Name)
}

func (p *fileSystemProvider) notifyRuleSetDeleted(event fsnotify.Event) {
	file := p.getFilePath(event)

	p.ruleSetChanged(RuleSetChangedEvent{
		Src:        "file_system:" + file,
		ChangeType: Remove,
	})
}

func (p *fileSystemProvider) notifyRuleSetCreated(event fsnotify.Event) {
	file := p.getFilePath(event)

	data, err := os.ReadFile(file)
	if err != nil {
		p.logger.Error().Err(err).Str("file", event.Name).Msg("Failed reading")

		return
	}

	p.ruleSetChanged(RuleSetChangedEvent{
		Src:        "file_system:" + event.Name,
		Definition: data,
		ChangeType: Create,
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
				p.logger.Warn().Msgf("Ignoring directory: %s", path)

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

		p.ruleSetChanged(RuleSetChangedEvent{
			Src:        "file_system:" + src,
			Definition: data,
			ChangeType: Create,
		})
	}

	return nil
}

func (p *fileSystemProvider) ruleSetChanged(evt RuleSetChangedEvent) {
	p.logger.Info().Str("src", evt.Src).Str("type", evt.ChangeType.String()).Msg("Rule set changed")
	p.queue <- evt
}
