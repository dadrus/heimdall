package secrets

import (
	"bytes"
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestDispatcherSchedule(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		initialState    bindingState
		wantCallbackRun bool
		wantState       bindingState
	}{
		"idle binding is scheduled and executed": {
			initialState:    bindingIdle,
			wantCallbackRun: true,
			wantState:       bindingIdle,
		},
		"scheduled binding is not scheduled again": {
			initialState:    bindingScheduled,
			wantCallbackRun: false,
			wantState:       bindingScheduled,
		},
		"running binding is not scheduled again": {
			initialState:    bindingRunning,
			wantCallbackRun: false,
			wantState:       bindingRunning,
		},
		"closed binding is ignored": {
			initialState:    bindingClosed,
			wantCallbackRun: false,
			wantState:       bindingClosed,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			dsp, err := newDispatcher(zerolog.Nop())
			require.NoError(t, err)

			defer dsp.stop()

			bdg := newBinding(bindingKey{source: "source", selector: "selector"}, zerolog.Nop())
			bdg.state = tc.initialState

			var calls atomic.Int32

			bdg.addSubscriber(func(context.Context) error {
				calls.Add(1)

				return nil
			})

			dsp.schedule(bdg)

			if tc.wantCallbackRun {
				require.Eventually(t, func() bool {
					return calls.Load() == 1
				}, time.Second, 10*time.Millisecond)
			} else {
				time.Sleep(150 * time.Millisecond)
				require.EqualValues(t, 0, calls.Load())
			}

			require.Equal(t, tc.wantState, bdg.state)
		})
	}
}

func TestDispatcherReschedule(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		initialState    bindingState
		wantCallbackRun bool
		wantState       bindingState
	}{
		"scheduled binding is executed": {
			initialState:    bindingScheduled,
			wantCallbackRun: true,
			wantState:       bindingIdle,
		},
		"idle binding is ignored by run": {
			initialState:    bindingIdle,
			wantCallbackRun: false,
			wantState:       bindingIdle,
		},
		"running binding is ignored by run": {
			initialState:    bindingRunning,
			wantCallbackRun: false,
			wantState:       bindingRunning,
		},
		"closed binding is ignored by run": {
			initialState:    bindingClosed,
			wantCallbackRun: false,
			wantState:       bindingClosed,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			dsp, err := newDispatcher(zerolog.Nop())
			require.NoError(t, err)

			defer dsp.stop()

			bdg := newBinding(bindingKey{source: "source", selector: "selector"}, zerolog.Nop())
			bdg.state = tc.initialState

			var calls atomic.Int32

			bdg.addSubscriber(func(context.Context) error {
				calls.Add(1)

				return nil
			})

			dsp.reschedule(bdg)

			if tc.wantCallbackRun {
				require.Eventually(t, func() bool {
					return calls.Load() == 1
				}, time.Second, 10*time.Millisecond)
			} else {
				time.Sleep(150 * time.Millisecond)
				require.EqualValues(t, 0, calls.Load())
			}

			require.Equal(t, tc.wantState, bdg.state)
		})
	}
}

func TestDispatcherRun(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		initialState         bindingState
		setEventPending      bool
		wantCalls            int32
		wantFinalState       bindingState
		wantEventPending     bool
		wantRunSynchronously bool
	}{
		"scheduled binding runs once": {
			initialState:         bindingScheduled,
			wantCalls:            1,
			wantFinalState:       bindingIdle,
			wantRunSynchronously: true,
		},
		"non scheduled binding is ignored": {
			initialState:         bindingIdle,
			wantCalls:            0,
			wantFinalState:       bindingIdle,
			wantRunSynchronously: true,
		},
		"pending event is rescheduled": {
			initialState:     bindingScheduled,
			setEventPending:  true,
			wantCalls:        2,
			wantFinalState:   bindingIdle,
			wantEventPending: false,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			dsp, err := newDispatcher(zerolog.Nop())
			require.NoError(t, err)

			defer dsp.stop()

			bdg := newBinding(bindingKey{source: "source", selector: "selector"}, zerolog.Nop())
			bdg.state = tc.initialState

			var calls atomic.Int32

			bdg.addSubscriber(func(context.Context) error {
				call := calls.Add(1)
				if call == 1 && tc.setEventPending {
					bdg.stateMu.Lock()
					bdg.eventPending = true
					bdg.stateMu.Unlock()
				}

				return nil
			})

			dsp.run(bdg)

			require.Eventually(t, func() bool {
				return calls.Load() == tc.wantCalls
			}, time.Second, 10*time.Millisecond)

			require.Equal(t, tc.wantFinalState, bdg.state)
			require.Equal(t, tc.wantEventPending, bdg.eventPending)
		})
	}
}

func TestDispatcherDispatch(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		payload         any
		wantCallbackRun bool
		wantLogContains []string
	}{
		"runs binding payload": {
			payload:         nil, // set inside test
			wantCallbackRun: true,
		},
		"logs invalid payload": {
			payload: "not-a-binding",
			wantLogContains: []string{
				"Invalid secret update dispatch payload",
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			var logs bytes.Buffer

			logger := zerolog.New(&logs)

			dsp, err := newDispatcher(logger)
			require.NoError(t, err)

			defer dsp.stop()

			var calls atomic.Int32

			payload := tc.payload
			if payload == nil {
				bdg := newBinding(bindingKey{source: "source", selector: "selector"}, zerolog.Nop())
				bdg.state = bindingScheduled
				bdg.addSubscriber(func(context.Context) error {
					calls.Add(1)

					return nil
				})

				payload = bdg
			}

			dsp.dispatch(payload)

			if tc.wantCallbackRun {
				require.EqualValues(t, 1, calls.Load())
			} else {
				require.EqualValues(t, 0, calls.Load())
			}

			logOutput := logs.String()
			for _, expected := range tc.wantLogContains {
				require.Contains(t, logOutput, expected)
			}
		})
	}
}

func TestDispatcherScheduleInvokeError(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		operation        func(*dispatcher, *binding)
		initialState     bindingState
		wantState        bindingState
		wantEventPending bool
		wantLogContains  []string
	}{
		"schedule unschedules binding when pool invoke fails": {
			operation: func(dsp *dispatcher, bdg *binding) {
				dsp.schedule(bdg)
			},
			initialState:     bindingIdle,
			wantState:        bindingIdle,
			wantEventPending: false,
			wantLogContains: []string{
				"Failed scheduling secret update callback",
			},
		},
		"reschedule unschedules binding when pool invoke fails": {
			operation: func(dsp *dispatcher, bdg *binding) {
				dsp.reschedule(bdg)
			},
			initialState:     bindingScheduled,
			wantState:        bindingIdle,
			wantEventPending: false,
			wantLogContains: []string{
				"Failed rescheduling secret update callback",
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			var logs bytes.Buffer

			logger := zerolog.New(&logs)

			dsp, err := newDispatcher(logger)
			require.NoError(t, err)

			dsp.stop()

			bdg := newBinding(
				bindingKey{source: "source", namespace: "namespace", selector: "selector"},
				zerolog.Nop(),
			)
			bdg.state = tc.initialState
			bdg.eventPending = true

			tc.operation(dsp, bdg)

			require.Equal(t, tc.wantState, bdg.state)
			require.Equal(t, tc.wantEventPending, bdg.eventPending)

			logOutput := logs.String()
			for _, expected := range tc.wantLogContains {
				require.Contains(t, logOutput, expected)
			}
		})
	}
}
