package provider

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
)

type fileSystemProvider struct {
	src     os.FileInfo
	watcher *fsnotify.Watcher
	queue   RuleSetChangedEventQueue
}

func registerFileSystemProvider(lifecycle fx.Lifecycle, logger zerolog.Logger, c config.Configuration, queue RuleSetChangedEventQueue) {
	provider, err := newFileSystemProvider(c, queue)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to load file system based provider for rule definitions")
		return
	}

	lifecycle.Append(
		fx.Hook{
			OnStart: func(ctx context.Context) error {
				logger.Info().Msg("Starting file system based provider for rule definitions")
				return provider.Start()
			},
			OnStop: func(ctx context.Context) error {
				logger.Info().Msg("Tearing down file system based provider for rule definitions")
				return provider.Stop()
			},
		},
	)
}

func newFileSystemProvider(c config.Configuration, queue RuleSetChangedEventQueue) (*fileSystemProvider, error) {
	if len(c.Rules.Providers.File.Src) == 0 {
		return nil, errors.New("invalid configuration for file provider")
	}

	fi, err := os.Stat(c.Rules.Providers.File.Src)
	if err != nil {
		return nil, err
	}

	var watcher *fsnotify.Watcher
	if c.Rules.Providers.File.Watch {
		watcher, err = fsnotify.NewWatcher()
		if err != nil {
			return nil, err
		}
	}

	return &fileSystemProvider{
		src:     fi,
		watcher: watcher,
		queue:   queue,
	}, nil
}

func (p *fileSystemProvider) Start() error {
	if err := p.readSource(p.src.Name()); err != nil {
		return err
	}

	if p.watcher != nil {
		p.watcher.Add(p.src.Name())
		go func() {
			for {
				select {
				case event, ok := <-p.watcher.Events:
					if !ok {
						return
					}
					if event.Op&fsnotify.Create == fsnotify.Create {
						data, err := os.ReadFile(event.Name)
						if err != nil {
							fmt.Printf("Failed to read %s: %s", event.Name, err)
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
					}
				case err, ok := <-p.watcher.Errors:
					if !ok {
						return
					}
					fmt.Println("error:", err)
				}
			}
		}()
	}
	return nil
}

func (p *fileSystemProvider) Stop() error {
	if p.watcher != nil {
		return p.watcher.Close()
	}
	return nil
}

func (p *fileSystemProvider) readSource(file string) error {
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
			fmt.Printf("Failed to read %s: %s", src, err)
		}

		p.ruleSetChanged(RuleSetChangedEvent{
			Src:        src,
			Definition: data,
			ChangeType: Create,
		})
	}

	return nil
}

func (p *fileSystemProvider) ruleSetChanged(evt RuleSetChangedEvent) {
	p.queue <- evt
}
