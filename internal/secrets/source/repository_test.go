package source

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/secrets/provider"
	providermocks "github.com/dadrus/heimdall/internal/secrets/provider/mocks"
	"github.com/dadrus/heimdall/internal/secrets/registry"
	"github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/x/task"
)

func TestSourceListLookup(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		sourceName string
		assert     func(t *testing.T, src *secretSource, err error)
	}{
		"finds source by name": {
			sourceName: "inline",
			assert: func(t *testing.T, src *secretSource, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, "inline", src.Name())
			},
		},
		"returns error for unknown source": {
			sourceName: "vault",
			assert: func(t *testing.T, src *secretSource, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, types.ErrSourceNotFound)
				require.Nil(t, src)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			srcs := sourceList{
				{name: "pem"},
				{name: "inline"},
			}

			src, err := srcs.lookup(tc.sourceName)

			tc.assert(t, src, err)
		})
	}
}

func TestSourceListStart(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, calls *guardedCalls) sourceList
		assert func(t *testing.T, srcs sourceList, calls *guardedCalls, err error)
	}{
		"starts sources in order": {
			setup: func(t *testing.T, calls *guardedCalls) sourceList {
				t.Helper()

				return sourceList{
					sourceWithMockProvider(t, "a", func(prv *providermocks.ProviderMock) {
						prv.EXPECT().
							Start(mock.Anything).
							Run(func(context.Context) {
								calls.Add("a:start")
							}).
							Return(nil)
					}),
					sourceWithMockProvider(t, "b", func(prv *providermocks.ProviderMock) {
						prv.EXPECT().
							Start(mock.Anything).
							Run(func(context.Context) {
								calls.Add("b:start")
							}).
							Return(nil)
					}),
				}
			},
			assert: func(t *testing.T, _ sourceList, calls *guardedCalls, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, []string{"a:start", "b:start"}, calls.All())
			},
		},
		"shuts down already started sources if start fails": {
			setup: func(t *testing.T, calls *guardedCalls) sourceList {
				t.Helper()

				return sourceList{
					sourceWithMockProvider(t, "a", func(prv *providermocks.ProviderMock) {
						prv.EXPECT().
							Start(mock.Anything).
							Run(func(context.Context) {
								calls.Add("a:start")
							}).
							Return(nil)

						prv.EXPECT().
							Stop(mock.Anything).
							Run(func(context.Context) {
								calls.Add("a:stop")
							}).
							Return(nil)
					}),
					sourceWithMockProvider(t, "b", func(prv *providermocks.ProviderMock) {
						prv.EXPECT().
							Start(mock.Anything).
							Run(func(context.Context) {
								calls.Add("b:start")
							}).
							Return(assert.AnError)
					}),
					sourceWithMockProvider(t, "c", func(prv *providermocks.ProviderMock) {
						prv.EXPECT().Start(mock.Anything).Maybe().Return(nil)
					}),
				}
			},
			assert: func(t *testing.T, srcs sourceList, calls *guardedCalls, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)
				require.Equal(t, []string{"a:start", "b:start", "a:stop"}, calls.All())
				require.False(t, srcs[0].Schedule())
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			var calls guardedCalls

			srcs := tc.setup(t, &calls)
			err := srcs.start(context.Background())

			tc.assert(t, srcs, &calls, err)
		})
	}
}

func TestSourceListShutdown(t *testing.T) {
	t.Parallel()

	firstErr := errors.New("first stop error")
	secondErr := errors.New("second stop error")

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, calls *guardedCalls) sourceList
		assert func(t *testing.T, srcs sourceList, calls *guardedCalls, err error)
	}{
		"stops sources in reverse order": {
			setup: func(t *testing.T, calls *guardedCalls) sourceList {
				t.Helper()

				return sourceList{
					sourceWithMockProvider(t, "a", func(prv *providermocks.ProviderMock) {
						prv.EXPECT().
							Stop(mock.Anything).
							Run(func(context.Context) {
								calls.Add("a:stop")
							}).
							Return(nil)
					}),
					sourceWithMockProvider(t, "b", func(prv *providermocks.ProviderMock) {
						prv.EXPECT().
							Stop(mock.Anything).
							Run(func(context.Context) {
								calls.Add("b:stop")
							}).
							Return(nil)
					}),
					sourceWithMockProvider(t, "c", func(prv *providermocks.ProviderMock) {
						prv.EXPECT().
							Stop(mock.Anything).
							Run(func(context.Context) {
								calls.Add("c:stop")
							}).
							Return(nil)
					}),
				}
			},
			assert: func(t *testing.T, srcs sourceList, calls *guardedCalls, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, []string{"c:stop", "b:stop", "a:stop"}, calls.All())

				for _, src := range srcs {
					require.False(t, src.Schedule())
				}
			},
		},
		"returns first stop error but still stops all sources": {
			setup: func(t *testing.T, calls *guardedCalls) sourceList {
				t.Helper()

				return sourceList{
					sourceWithMockProvider(t, "a", func(prv *providermocks.ProviderMock) {
						prv.EXPECT().
							Stop(mock.Anything).
							Run(func(context.Context) {
								calls.Add("a:stop")
							}).
							Return(nil)
					}),
					sourceWithMockProvider(t, "b", func(prv *providermocks.ProviderMock) {
						prv.EXPECT().
							Stop(mock.Anything).
							Run(func(context.Context) {
								calls.Add("b:stop")
							}).
							Return(secondErr)
					}),
					sourceWithMockProvider(t, "c", func(prv *providermocks.ProviderMock) {
						prv.EXPECT().
							Stop(mock.Anything).
							Run(func(context.Context) {
								calls.Add("c:stop")
							}).
							Return(firstErr)
					}),
				}
			},
			assert: func(t *testing.T, _ sourceList, calls *guardedCalls, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, firstErr)
				require.NotErrorIs(t, err, secondErr)
				require.Equal(t, []string{"c:stop", "b:stop", "a:stop"}, calls.All())
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			var calls guardedCalls

			srcs := tc.setup(t, &calls)
			err := srcs.shutdown(context.Background())

			tc.assert(t, srcs, &calls, err)
		})
	}
}

func TestNewRepository(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T) *config.Configuration
		assert func(t *testing.T, repo Repository, err error)
	}{
		"creates and orders sources by dependencies": {
			setup: func(t *testing.T) *config.Configuration {
				t.Helper()

				typeA := uniqueProviderType(t, "a")
				typeB := uniqueProviderType(t, "b")
				typeC := uniqueProviderType(t, "c")

				registerProvider(t, typeA, func(t *testing.T, args provider.Args) provider.Provider {
					t.Helper()

					require.NotNil(t, args.Observer)
					require.NotNil(t, args.Resolver)

					prv := providermocks.NewProviderMock(t)
					prv.EXPECT().Dependencies().Return(nil)
					prv.EXPECT().Stop(mock.Anything).Return(nil).Maybe()

					return prv
				})

				registerProvider(t, typeB, func(t *testing.T, args provider.Args) provider.Provider {
					t.Helper()

					require.NotNil(t, args.Observer)
					require.NotNil(t, args.Resolver)

					prv := providermocks.NewProviderMock(t)
					prv.EXPECT().
						Dependencies().
						Return([]types.Reference{{Source: "a", Selector: "server"}})
					prv.EXPECT().Stop(mock.Anything).Return(nil).Maybe()

					return prv
				})

				registerProvider(t, typeC, func(t *testing.T, args provider.Args) provider.Provider {
					t.Helper()

					require.NotNil(t, args.Observer)
					require.NotNil(t, args.Resolver)

					prv := providermocks.NewProviderMock(t)
					prv.EXPECT().
						Dependencies().
						Return([]types.Reference{{Source: "b", Selector: "client"}})
					prv.EXPECT().Stop(mock.Anything).Return(nil).Maybe()

					return prv
				})

				return &config.Configuration{
					SecretManagement: map[string]config.SecretSourceConfig{
						"a": {Type: typeA},
						"b": {Type: typeB},
						"c": {Type: typeC},
					},
				}
			},
			assert: func(t *testing.T, repo Repository, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, repo)

				t.Cleanup(func() {
					require.NoError(t, repo.Stop(context.Background()))
				})

				impl := repo.(*repositoryImpl)

				require.Equal(t, []string{"a", "b", "c"}, sourceNames(impl.sources))

				src, err := repo.Lookup("b")
				require.NoError(t, err)
				require.Equal(t, "b", src.Name())
			},
		},
		"returns provider creation error": {
			setup: func(t *testing.T) *config.Configuration {
				t.Helper()

				providerType := uniqueProviderType(t, "failing")

				registry.Register(providerType, provider.FactoryFunc(func(provider.Args) (provider.Provider, error) {
					return nil, assert.AnError
				}))
				t.Cleanup(func() {
					registry.Unregister(providerType)
				})

				return &config.Configuration{
					SecretManagement: map[string]config.SecretSourceConfig{
						"failing": {Type: providerType},
					},
				}
			},
			assert: func(t *testing.T, repo Repository, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)
				require.Nil(t, repo)
			},
		},
		"returns unsupported provider type error": {
			setup: func(t *testing.T) *config.Configuration {
				t.Helper()

				return &config.Configuration{
					SecretManagement: map[string]config.SecretSourceConfig{
						"missing": {Type: "does-not-exist"},
					},
				}
			},
			assert: func(t *testing.T, repo Repository, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, types.ErrUnsupportedProviderType)
				require.Nil(t, repo)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			cfg := tc.setup(t)

			repo, err := NewRepository(cfg, zerolog.Nop(), nil, providermocks.NewDependenciesResolverMock(t))

			tc.assert(t, repo, err)
		})
	}
}

func TestRepositoryObserverNotify(t *testing.T) {
	t.Parallel()

	event := Event{
		Source: "pem",
		Selectors: []Selector{
			{Value: "server"},
		},
	}

	observer := NewObserverMock(t)
	observer.EXPECT().Notify(event)

	repo := &repositoryImpl{
		executor: mustNewExecutor(t),
	}
	t.Cleanup(repo.executor.Stop)

	repo.AddObserver(observer)

	ro := &repositoryObserver{r: repo}
	ro.Notify(event)
}

func TestRepositoryAddObserver(t *testing.T) {
	t.Parallel()

	repo := &repositoryImpl{}

	observerA := NewObserverMock(t)
	observerA.EXPECT().Notify(Event{Source: "pem"})

	observerB := NewObserverMock(t)
	observerB.EXPECT().Notify(Event{Source: "pem"})

	repo.AddObserver(nil)
	repo.AddObserver(observerA)
	repo.AddObserver(observerB)

	repo.notifyObservers(Event{Source: "pem"})
}

func TestRepositoryLookup(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		sourceName string
		assert     func(t *testing.T, src Source, err error)
	}{
		"returns matching source": {
			sourceName: "pem",
			assert: func(t *testing.T, src Source, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, "pem", src.Name())
			},
		},
		"returns error for unknown source": {
			sourceName: "vault",
			assert: func(t *testing.T, src Source, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, types.ErrSourceNotFound)
				require.Nil(t, src)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			repo := &repositoryImpl{
				sources: sourceList{
					{name: "pem"},
					{name: "inline"},
				},
			}

			src, err := repo.Lookup(tc.sourceName)

			tc.assert(t, src, err)
		})
	}
}

func TestRepositoryStartStop(t *testing.T) {
	t.Parallel()

	var calls guardedCalls

	repo := &repositoryImpl{
		executor: mustNewExecutor(t),
		sources: sourceList{
			sourceWithMockProvider(t, "a", func(prv *providermocks.ProviderMock) {
				prv.EXPECT().
					Start(mock.Anything).
					Run(func(context.Context) {
						calls.Add("a:start")
					}).
					Return(nil)

				prv.EXPECT().
					Stop(mock.Anything).
					Run(func(context.Context) {
						calls.Add("a:stop")
					}).
					Return(nil)
			}),
			sourceWithMockProvider(t, "b", func(prv *providermocks.ProviderMock) {
				prv.EXPECT().
					Start(mock.Anything).
					Run(func(context.Context) {
						calls.Add("b:start")
					}).
					Return(nil)

				prv.EXPECT().
					Stop(mock.Anything).
					Run(func(context.Context) {
						calls.Add("b:stop")
					}).
					Return(nil)
			}),
		},
	}

	require.NoError(t, repo.Start(context.Background()))
	require.NoError(t, repo.Stop(context.Background()))

	require.Equal(t, []string{
		"a:start",
		"b:start",
		"b:stop",
		"a:stop",
	}, calls.All())
}

func TestRepositoryHandleEvent(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		event  Event
		setup  func(t *testing.T, calls *guardedCalls) *repositoryImpl
		assert func(t *testing.T, calls *guardedCalls)
	}{
		"schedules dependent source restart and notifies observers": {
			event: Event{
				Source: "base",
				Selectors: []Selector{
					{Value: "server"},
				},
			},
			setup: func(t *testing.T, calls *guardedCalls) *repositoryImpl {
				t.Helper()

				observer := NewObserverMock(t)
				observer.EXPECT().Notify(Event{
					Source: "base",
					Selectors: []Selector{
						{Value: "server"},
					},
				})

				restartObserver := NewObserverMock(t)
				restartObserver.EXPECT().Notify(Event{Source: "dependent"})

				dependent := &secretSource{
					name: "dependent",
					sr: &secretsResolver{
						deps: []types.Reference{{Source: "base", Selector: "server"}},
					},
					p: providerWithMock(t, func(prv *providermocks.ProviderMock) {
						prv.EXPECT().
							Stop(mock.Anything).
							Run(func(context.Context) {
								calls.Add("dependent:stop")
							}).
							Return(nil)

						prv.EXPECT().
							Start(mock.Anything).
							Run(func(context.Context) {
								calls.Add("dependent:start")
							}).
							Return(nil)
					}),
					logger:   zerolog.Nop(),
					observer: restartObserver,
				}

				repo := &repositoryImpl{
					executor: mustNewExecutor(t),
					sources: sourceList{
						sourceWithMockProvider(t, "base", func(*providermocks.ProviderMock) {}),
						dependent,
					},
				}
				repo.AddObserver(observer)

				return repo
			},
			assert: func(t *testing.T, calls *guardedCalls) {
				t.Helper()

				require.Eventually(t, func() bool {
					return assert.ObjectsAreEqual(
						[]string{"dependent:stop", "dependent:start"},
						calls.All(),
					)
				}, time.Second, 10*time.Millisecond)
			},
		},
		"does not restart non dependent sources": {
			event: Event{Source: "base"},
			setup: func(t *testing.T, _ *guardedCalls) *repositoryImpl {
				t.Helper()

				observer := NewObserverMock(t)
				observer.EXPECT().Notify(Event{Source: "base"})

				independent := &secretSource{
					name: "independent",
					sr: &secretsResolver{
						deps: []types.Reference{{Source: "other", Selector: "server"}},
					},
					p:        providerWithMock(t, func(*providermocks.ProviderMock) {}),
					logger:   zerolog.Nop(),
					observer: NewObserverMock(t),
				}

				repo := &repositoryImpl{
					executor: mustNewExecutor(t),
					sources:  sourceList{independent},
				}
				repo.AddObserver(observer)

				return repo
			},
			assert: func(t *testing.T, calls *guardedCalls) {
				t.Helper()

				require.Never(t, func() bool {
					return len(calls.All()) != 0
				}, 100*time.Millisecond, 10*time.Millisecond)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			var calls guardedCalls

			repo := tc.setup(t, &calls)

			t.Cleanup(repo.executor.Stop)

			repo.handleEvent(tc.event)

			tc.assert(t, &calls)
		})
	}
}

func TestOrderSources(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		sources map[string]*secretSource
		assert  func(t *testing.T, ordered sourceList, err error)
	}{
		"orders sources by dependencies": {
			sources: map[string]*secretSource{
				"a": {
					name: "a",
					sr:   &secretsResolver{},
				},
				"b": {
					name: "b",
					sr: &secretsResolver{
						deps: []types.Reference{{Source: "a", Selector: "server"}},
					},
				},
				"c": {
					name: "c",
					sr: &secretsResolver{
						deps: []types.Reference{{Source: "b", Selector: "client"}},
					},
				},
			},
			assert: func(t *testing.T, ordered sourceList, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, []string{"a", "b", "c"}, sourceNames(ordered))
			},
		},
		"returns error for missing dependency source": {
			sources: map[string]*secretSource{
				"a": {
					name: "a",
					sr: &secretsResolver{
						deps: []types.Reference{{Source: "missing", Selector: "server"}},
					},
				},
			},
			assert: func(t *testing.T, ordered sourceList, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.Nil(t, ordered)
			},
		},
		"returns error for cyclic dependencies": {
			sources: map[string]*secretSource{
				"a": {
					name: "a",
					sr: &secretsResolver{
						deps: []types.Reference{{Source: "b", Selector: "server"}},
					},
				},
				"b": {
					name: "b",
					sr: &secretsResolver{
						deps: []types.Reference{{Source: "a", Selector: "client"}},
					},
				},
			},
			assert: func(t *testing.T, ordered sourceList, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.Nil(t, ordered)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			ordered, err := orderSources(tc.sources)

			tc.assert(t, ordered, err)
		})
	}
}

type guardedCalls struct {
	mu    sync.Mutex
	calls []string
}

func (c *guardedCalls) Add(call string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.calls = append(c.calls, call)
}

func (c *guardedCalls) All() []string {
	c.mu.Lock()
	defer c.mu.Unlock()

	return slices.Clone(c.calls)
}

func sourceWithMockProvider(
	t *testing.T,
	name string,
	setup func(*providermocks.ProviderMock),
) *secretSource {
	t.Helper()

	return &secretSource{
		name:     name,
		sr:       &secretsResolver{},
		p:        providerWithMock(t, setup),
		logger:   zerolog.Nop(),
		observer: NewObserverMock(t),
	}
}

func providerWithMock(
	t *testing.T,
	setup func(*providermocks.ProviderMock),
) provider.Provider {
	t.Helper()

	prv := providermocks.NewProviderMock(t)

	if setup != nil {
		setup(prv)
	}

	return prv
}

func sourceNames(srcs sourceList) []string {
	names := make([]string, 0, len(srcs))

	for _, src := range srcs {
		names = append(names, src.Name())
	}

	return names
}

func mustNewExecutor(t *testing.T) *task.Executor {
	t.Helper()

	executor, err := task.NewExecutor(4)
	require.NoError(t, err)

	return executor
}

func registerProvider(
	t *testing.T,
	providerType string,
	create func(t *testing.T, args provider.Args) provider.Provider,
) {
	t.Helper()

	registry.Register(providerType, provider.FactoryFunc(func(args provider.Args) (provider.Provider, error) {
		return create(t, args), nil
	}))

	t.Cleanup(func() {
		registry.Unregister(providerType)
	})
}
