package secrets

import (
	"bytes"
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBindingSubscriberManagement(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		subscribersToAdd    int
		subscribersToRemove int
		wantRemaining       bool
	}{
		"returns false after removing only subscriber": {
			subscribersToAdd:    1,
			subscribersToRemove: 1,
			wantRemaining:       false,
		},
		"returns true when subscribers remain": {
			subscribersToAdd:    2,
			subscribersToRemove: 1,
			wantRemaining:       true,
		},
		"returns false after removing all subscribers": {
			subscribersToAdd:    2,
			subscribersToRemove: 2,
			wantRemaining:       false,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			bdg := newBinding(bindingKey{source: "source", selector: "selector"}, zerolog.Nop())
			defer bdg.stop()

			ids := make([]uint64, 0, tc.subscribersToAdd)
			for range tc.subscribersToAdd {
				ids = append(ids, bdg.addSubscriber(func(context.Context) error { return nil }))
			}

			var remaining bool
			for idx := range tc.subscribersToRemove {
				remaining = bdg.removeSubscriber(ids[idx])
			}

			require.Equal(t, tc.wantRemaining, remaining)
		})
	}
}

func TestBindingSchedule(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		initialState  bindingState
		wantState     bindingState
		wantScheduled bool
		wantPending   bool
	}{
		"idle schedules binding": {
			initialState:  bindingIdle,
			wantState:     bindingScheduled,
			wantScheduled: true,
			wantPending:   true,
		},
		"already scheduled only marks event pending": {
			initialState:  bindingScheduled,
			wantState:     bindingScheduled,
			wantScheduled: false,
			wantPending:   true,
		},
		"running only marks event pending": {
			initialState:  bindingRunning,
			wantState:     bindingRunning,
			wantScheduled: false,
			wantPending:   true,
		},
		"closed ignores schedule": {
			initialState:  bindingClosed,
			wantState:     bindingClosed,
			wantScheduled: false,
			wantPending:   false,
		},
		"unknown state is not scheduled": {
			initialState:  bindingState(99),
			wantState:     bindingState(99),
			wantScheduled: false,
			wantPending:   true,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			bdg := newBinding(bindingKey{source: "source", selector: "selector"}, zerolog.Nop())
			bdg.state = tc.initialState

			scheduled := bdg.schedule()

			require.Equal(t, tc.wantScheduled, scheduled)
			require.Equal(t, tc.wantState, bdg.state)
			require.Equal(t, tc.wantPending, bdg.eventPending)
		})
	}
}

func TestBindingUnschedule(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		initialState   bindingState
		initialPending bool
		wantState      bindingState
		wantPending    bool
	}{
		"scheduled binding is reset to idle": {
			initialState:   bindingScheduled,
			initialPending: true,
			wantState:      bindingIdle,
			wantPending:    false,
		},
		"idle binding is unchanged": {
			initialState:   bindingIdle,
			initialPending: true,
			wantState:      bindingIdle,
			wantPending:    true,
		},
		"running binding is unchanged": {
			initialState:   bindingRunning,
			initialPending: true,
			wantState:      bindingRunning,
			wantPending:    true,
		},
		"closed binding is unchanged": {
			initialState:   bindingClosed,
			initialPending: true,
			wantState:      bindingClosed,
			wantPending:    true,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			bdg := newBinding(bindingKey{source: "source", selector: "selector"}, zerolog.Nop())
			bdg.state = tc.initialState
			bdg.eventPending = tc.initialPending

			bdg.unschedule()

			require.Equal(t, tc.wantState, bdg.state)
			require.Equal(t, tc.wantPending, bdg.eventPending)
		})
	}
}

func TestBindingBeginRun(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		initialState bindingState
		wantStarted  bool
		wantState    bindingState
	}{
		"scheduled binding starts running": {
			initialState: bindingScheduled,
			wantStarted:  true,
			wantState:    bindingRunning,
		},
		"idle binding does not start running": {
			initialState: bindingIdle,
			wantStarted:  false,
			wantState:    bindingIdle,
		},
		"running binding does not start again": {
			initialState: bindingRunning,
			wantStarted:  false,
			wantState:    bindingRunning,
		},
		"closed binding does not start running": {
			initialState: bindingClosed,
			wantStarted:  false,
			wantState:    bindingClosed,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			bdg := newBinding(bindingKey{source: "source", selector: "selector"}, zerolog.Nop())
			bdg.state = tc.initialState

			started := bdg.beginRun()

			require.Equal(t, tc.wantStarted, started)
			require.Equal(t, tc.wantState, bdg.state)

			if started {
				bdg.finishRun()
			}
		})
	}
}

func TestBindingFinishRun(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		initialState        bindingState
		initialEventPending bool
		wantScheduleAgain   bool
		wantState           bindingState
		wantEventPending    bool
	}{
		"running binding without pending event becomes idle": {
			initialState:        bindingRunning,
			initialEventPending: false,
			wantScheduleAgain:   false,
			wantState:           bindingIdle,
			wantEventPending:    false,
		},
		"running binding with pending event becomes scheduled": {
			initialState:        bindingRunning,
			initialEventPending: true,
			wantScheduleAgain:   true,
			wantState:           bindingScheduled,
			wantEventPending:    true,
		},
		"closed binding stays closed": {
			initialState:        bindingClosed,
			initialEventPending: true,
			wantScheduleAgain:   false,
			wantState:           bindingClosed,
			wantEventPending:    true,
		},
		"unexpected idle state becomes idle": {
			initialState:        bindingIdle,
			initialEventPending: false,
			wantScheduleAgain:   false,
			wantState:           bindingIdle,
			wantEventPending:    false,
		},
		"unexpected scheduled state without pending event becomes idle": {
			initialState:        bindingScheduled,
			initialEventPending: false,
			wantScheduleAgain:   false,
			wantState:           bindingIdle,
			wantEventPending:    false,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			bdg := newBinding(bindingKey{source: "source", selector: "selector"}, zerolog.Nop())
			bdg.state = tc.initialState
			bdg.eventPending = tc.initialEventPending

			bdg.wg.Add(1)
			scheduleAgain := bdg.finishRun()

			require.Equal(t, tc.wantScheduleAgain, scheduleAgain)
			require.Equal(t, tc.wantState, bdg.state)
			require.Equal(t, tc.wantEventPending, bdg.eventPending)

			done := make(chan struct{})

			go func() {
				bdg.wg.Wait()

				close(done)
			}()

			select {
			case <-done:
			case <-time.After(500 * time.Millisecond):
				t.Fatal("finishRun did not mark run as done")
			}
		})
	}
}

func TestBindingRunCallbacks(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		callbacks       []func(*atomic.Int32) func(context.Context) error
		wantCalls       int32
		wantLogContains []string
	}{
		"runs no callbacks": {
			callbacks: nil,
			wantCalls: 0,
		},
		"runs one callback": {
			callbacks: []func(*atomic.Int32) func(context.Context) error{
				func(calls *atomic.Int32) func(context.Context) error {
					return func(context.Context) error {
						calls.Add(1)

						return nil
					}
				},
			},
			wantCalls: 1,
		},
		"runs multiple callbacks": {
			callbacks: []func(*atomic.Int32) func(context.Context) error{
				func(calls *atomic.Int32) func(context.Context) error {
					return func(context.Context) error {
						calls.Add(1)

						return nil
					}
				},
				func(calls *atomic.Int32) func(context.Context) error {
					return func(context.Context) error {
						calls.Add(1)

						return nil
					}
				},
			},
			wantCalls: 2,
		},
		"logs callback errors and continues": {
			callbacks: []func(*atomic.Int32) func(context.Context) error{
				func(calls *atomic.Int32) func(context.Context) error {
					return func(context.Context) error {
						calls.Add(1)

						return assert.AnError
					}
				},
				func(calls *atomic.Int32) func(context.Context) error {
					return func(context.Context) error {
						calls.Add(1)

						return nil
					}
				},
			},
			wantCalls: 2,
			wantLogContains: []string{
				"Secret update callback failed",
				"callback failed",
				"_source",
				"source",
				"_namespace",
				"namespace",
				"_selector",
				"selector",
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			var logs bytes.Buffer

			logger := zerolog.New(&logs)

			bdg := newBinding(
				bindingKey{source: "source", namespace: "namespace", selector: "selector"},
				logger,
			)

			var calls atomic.Int32
			for _, callbackFactory := range tc.callbacks {
				bdg.addSubscriber(callbackFactory(&calls))
			}

			bdg.runCallbacks()

			require.Equal(t, tc.wantCalls, calls.Load())

			logOutput := logs.String()
			for _, expected := range tc.wantLogContains {
				require.Contains(t, logOutput, expected)
			}

			if len(tc.wantLogContains) == 0 {
				require.Empty(t, logOutput)
			}
		})
	}
}

func TestBindingStop(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		initialState        bindingState
		initialEventPending bool
		running             bool
		wantState           bindingState
		wantEventPending    bool
		wantWait            bool
	}{
		"idle binding becomes closed": {
			initialState:        bindingIdle,
			initialEventPending: true,
			wantState:           bindingClosed,
			wantEventPending:    false,
		},
		"scheduled binding becomes closed": {
			initialState:        bindingScheduled,
			initialEventPending: true,
			wantState:           bindingClosed,
			wantEventPending:    false,
		},
		"closed binding remains closed": {
			initialState:        bindingClosed,
			initialEventPending: true,
			wantState:           bindingClosed,
			wantEventPending:    false,
		},
		"waits for running callback": {
			initialState:        bindingRunning,
			initialEventPending: true,
			running:             true,
			wantState:           bindingClosed,
			wantEventPending:    false,
			wantWait:            true,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			bdg := newBinding(bindingKey{source: "source", selector: "selector"}, zerolog.Nop())
			bdg.state = tc.initialState
			bdg.eventPending = tc.initialEventPending

			if tc.running {
				bdg.wg.Add(1)
			}

			stopped := make(chan struct{})

			var wg sync.WaitGroup
			wg.Go(func() {
				bdg.stop()
				close(stopped)
			})

			if tc.wantWait {
				select {
				case <-stopped:
					t.Fatal("binding stopped before running callback finished")
				case <-time.After(100 * time.Millisecond):
				}

				bdg.wg.Done()
			}

			select {
			case <-stopped:
			case <-time.After(500 * time.Millisecond):
				t.Fatal("binding did not stop")
			}

			wg.Wait()

			require.Equal(t, tc.wantState, bdg.state)
			require.Equal(t, tc.wantEventPending, bdg.eventPending)
		})
	}
}
