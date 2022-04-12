package provider

import (
	"context"
	"errors"
	"io/ioutil"
	"os"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
)

var ErrInvalidProviderConfiguration = errors.New("invalid provider configuration")

type fileSystemProvider struct {
	src     os.FileInfo
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

	fInfo, err := os.Stat(conf.Rules.Providers.File.Src)
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
		src:     fInfo,
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

	if err := p.watcher.Add(p.src.Name()); err != nil {
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

			if event.Op&fsnotify.Create == fsnotify.Create {
				data, err := os.ReadFile(event.Name)
				if err != nil {
					p.logger.Error().Err(err).Str("file", event.Name).Msg("Failed reading")

					return
				}

				p.ruleSetChanged(RuleSetChangedEvent{
					Src:        event.Name,
					Definition: data,
					ChangeType: Create,
				})
			} else if event.Op&fsnotify.Remove == fsnotify.Remove {
				p.ruleSetChanged(RuleSetChangedEvent{
					Src:        event.Name,
					ChangeType: Remove,
				})
			} else if event.Op&fsnotify.Write == fsnotify.Write {
				p.ruleSetChanged(RuleSetChangedEvent{
					Src:        event.Name,
					ChangeType: Remove,
				})

				data, err := os.ReadFile(event.Name)
				if err != nil {
					p.logger.Error().Err(err).Str("file", event.Name).Msg("Failed reading")

					return
				}

				if len(data) != 0 {
					p.ruleSetChanged(RuleSetChangedEvent{
						Src:        event.Name,
						Definition: data,
						ChangeType: Create,
					})
				}
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

	if p.src.IsDir() {
		files, _ := ioutil.ReadDir(p.src.Name())
		for _, file := range files {
			if !file.IsDir() {
				sources = append(sources, file.Name())
			}
		}
	} else {
		sources = append(sources, p.src.Name())
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
