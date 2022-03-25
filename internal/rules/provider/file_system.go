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
	src     string
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

	_, err := os.Stat(c.Rules.Providers.File.Src)
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
		src:     c.Rules.Providers.File.Src,
		watcher: watcher,
		queue:   queue,
	}, nil
}

func (p *fileSystemProvider) Start() error {
	if err := p.readContents(p.src); err != nil {
		return err
	}

	if p.watcher != nil {
		p.watcher.Add(p.src)
		go func() {
			for {
				select {
				case event, ok := <-p.watcher.Events:
					if !ok {
						return
					}
					if event.Op == fsnotify.Write {
						p.readContents(event.Name)
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

func (p *fileSystemProvider) readContents(file string) error {
	fi, err := os.Stat(file)
	if err != nil {
		return err
	}

	var sources []string
	if fi.IsDir() {
		files, _ := ioutil.ReadDir(fi.Name())
		for _, file := range files {
			if !file.IsDir() {
				sources = append(sources, file.Name())
			}
		}
	} else {
		sources = append(sources, fi.Name())
	}

	for _, src := range sources {
		f, err := os.Open(src)
		if err != nil {
			return err
		}

		data, err := ioutil.ReadAll(f)
		f.Close()
		if err != nil {
			return err
		}

		p.queue <- RuleSetChangedEvent{
			Src:        src,
			Definition: data,
			ChangeType: Create,
		}
	}

	return nil
}
