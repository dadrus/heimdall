package task

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestStateMachineSchedule(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		initialState        State
		initialEventPending bool
		wantScheduled       bool
		wantState           State
		wantEventPending    bool
	}{
		"idle state schedules task": {
			initialState:     StateIdle,
			wantScheduled:    true,
			wantState:        StateScheduled,
			wantEventPending: true,
		},
		"scheduled state marks event pending but does not schedule again": {
			initialState:     StateScheduled,
			wantScheduled:    false,
			wantState:        StateScheduled,
			wantEventPending: true,
		},
		"running state marks event pending but does not schedule again": {
			initialState:     StateRunning,
			wantScheduled:    false,
			wantState:        StateRunning,
			wantEventPending: true,
		},
		"closed state is ignored": {
			initialState:     StateClosed,
			wantScheduled:    false,
			wantState:        StateClosed,
			wantEventPending: false,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			var sm StateMachine

			sm.state = tc.initialState
			sm.eventPending = tc.initialEventPending

			require.Equal(t, tc.wantScheduled, sm.Schedule())
			require.Equal(t, tc.wantState, sm.state)
			require.Equal(t, tc.wantEventPending, sm.eventPending)
		})
	}
}

func TestStateMachineCancelSchedule(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		initialState        State
		initialEventPending bool
		wantState           State
		wantEventPending    bool
	}{
		"scheduled state is cancelled": {
			initialState:        StateScheduled,
			initialEventPending: true,
			wantState:           StateIdle,
			wantEventPending:    false,
		},
		"idle state is unchanged": {
			initialState:        StateIdle,
			initialEventPending: true,
			wantState:           StateIdle,
			wantEventPending:    true,
		},
		"running state is unchanged": {
			initialState:        StateRunning,
			initialEventPending: true,
			wantState:           StateRunning,
			wantEventPending:    true,
		},
		"closed state is unchanged": {
			initialState:        StateClosed,
			initialEventPending: true,
			wantState:           StateClosed,
			wantEventPending:    true,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			var sm StateMachine

			sm.state = tc.initialState
			sm.eventPending = tc.initialEventPending

			sm.CancelSchedule()

			require.Equal(t, tc.wantState, sm.state)
			require.Equal(t, tc.wantEventPending, sm.eventPending)
		})
	}
}

func TestStateMachineBeginRun(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		initialState        State
		initialEventPending bool
		wantBegin           bool
		wantState           State
		wantEventPending    bool
	}{
		"scheduled state begins run": {
			initialState:        StateScheduled,
			initialEventPending: true,
			wantBegin:           true,
			wantState:           StateRunning,
			wantEventPending:    false,
		},
		"idle state does not begin": {
			initialState:        StateIdle,
			initialEventPending: true,
			wantBegin:           false,
			wantState:           StateIdle,
			wantEventPending:    true,
		},
		"running state does not begin": {
			initialState:        StateRunning,
			initialEventPending: true,
			wantBegin:           false,
			wantState:           StateRunning,
			wantEventPending:    true,
		},
		"closed state does not begin": {
			initialState:        StateClosed,
			initialEventPending: true,
			wantBegin:           false,
			wantState:           StateClosed,
			wantEventPending:    true,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			var sm StateMachine

			sm.state = tc.initialState
			sm.eventPending = tc.initialEventPending

			require.Equal(t, tc.wantBegin, sm.BeginRun())
			require.Equal(t, tc.wantState, sm.state)
			require.Equal(t, tc.wantEventPending, sm.eventPending)

			if tc.wantBegin {
				require.False(t, sm.FinishRun())
			}
		})
	}
}

func TestStateMachineFinishRun(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		eventPending      bool
		stateBeforeFinish State
		wantReschedule    bool
		wantState         State
		wantEventPending  bool
	}{
		"finish run without pending event returns idle": {
			stateBeforeFinish: StateRunning,
			wantReschedule:    false,
			wantState:         StateIdle,
		},
		"finish run with pending event reschedules": {
			eventPending:      true,
			stateBeforeFinish: StateRunning,
			wantReschedule:    true,
			wantState:         StateScheduled,
			wantEventPending:  true,
		},
		"finish closed run does not reschedule": {
			eventPending:      true,
			stateBeforeFinish: StateClosed,
			wantReschedule:    false,
			wantState:         StateClosed,
			wantEventPending:  true,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			var sm StateMachine

			sm.state = StateScheduled
			require.True(t, sm.BeginRun())

			sm.state = tc.stateBeforeFinish
			sm.eventPending = tc.eventPending

			require.Equal(t, tc.wantReschedule, sm.FinishRun())
			require.Equal(t, tc.wantState, sm.state)
			require.Equal(t, tc.wantEventPending, sm.eventPending)
		})
	}
}

func TestStateMachineStop(t *testing.T) {
	t.Parallel()

	t.Run("closes state and clears pending event", func(t *testing.T) {
		t.Parallel()

		var sm StateMachine

		sm.state = StateScheduled
		sm.eventPending = true

		sm.Stop()

		require.Equal(t, StateClosed, sm.state)
		require.False(t, sm.eventPending)
	})

	t.Run("waits for running task to finish", func(t *testing.T) {
		t.Parallel()

		var sm StateMachine

		sm.state = StateScheduled
		require.True(t, sm.BeginRun())

		stopped := make(chan struct{})

		go func() {
			sm.Stop()
			close(stopped)
		}()

		require.Never(t, func() bool {
			select {
			case <-stopped:
				return true
			default:
				return false
			}
		}, 100*time.Millisecond, 10*time.Millisecond)

		require.False(t, sm.FinishRun())

		require.Eventually(t, func() bool {
			select {
			case <-stopped:
				return true
			default:
				return false
			}
		}, time.Second, 10*time.Millisecond)

		require.Equal(t, StateClosed, sm.state)
	})

	t.Run("is concurrency safe for multiple Stop calls", func(t *testing.T) {
		t.Parallel()

		var sm StateMachine

		sm.state = StateScheduled
		require.True(t, sm.BeginRun())

		var wg sync.WaitGroup

		for range 5 {
			wg.Go(func() {
				sm.Stop()
			})
		}

		require.False(t, sm.FinishRun())

		done := make(chan struct{})

		go func() {
			wg.Wait()
			close(done)
		}()

		require.Eventually(t, func() bool {
			select {
			case <-done:
				return true
			default:
				return false
			}
		}, time.Second, 10*time.Millisecond)
	})
}
