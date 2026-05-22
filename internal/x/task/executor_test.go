package task

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type testTask struct {
	StateMachine

	runFunc func()

	unscheduleCalls atomic.Int32
	unscheduleErr   atomic.Value // error
}

func (t *testTask) Unschedule(reason error) {
	t.CancelSchedule()
	t.unscheduleCalls.Add(1)

	if reason != nil {
		t.unscheduleErr.Store(reason)
	}
}

func (t *testTask) Run() {
	if t.runFunc != nil {
		t.runFunc()
	}
}

func setTaskState(tsk *testTask, state State, eventPending bool) {
	tsk.stateMu.Lock()
	defer tsk.stateMu.Unlock()

	tsk.state = state
	tsk.eventPending = eventPending
}

func taskState(tsk *testTask) (State, bool) {
	tsk.stateMu.Lock()
	defer tsk.stateMu.Unlock()

	return tsk.state, tsk.eventPending
}

func TestExecutorSchedule(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		initialState     State
		wantRun          bool
		wantState        State
		wantEventPending bool
	}{
		"idle task is scheduled and executed": {
			initialState:     StateIdle,
			wantRun:          true,
			wantState:        StateIdle,
			wantEventPending: false,
		},
		"scheduled task is not scheduled again": {
			initialState:     StateScheduled,
			wantRun:          false,
			wantState:        StateScheduled,
			wantEventPending: true,
		},
		"running task is not scheduled again": {
			initialState:     StateRunning,
			wantRun:          false,
			wantState:        StateRunning,
			wantEventPending: true,
		},
		"closed task is ignored": {
			initialState:     StateClosed,
			wantRun:          false,
			wantState:        StateClosed,
			wantEventPending: false,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			executor, err := NewExecutor(1)
			require.NoError(t, err)

			defer executor.Stop()

			var calls atomic.Int32

			tsk := &testTask{
				runFunc: func() {
					calls.Add(1)
				},
			}
			setTaskState(tsk, tc.initialState, false)

			executor.Schedule(tsk)

			if tc.wantRun {
				require.Eventually(t, func() bool {
					return calls.Load() == 1
				}, time.Second, 10*time.Millisecond)
			} else {
				require.Never(t, func() bool {
					return calls.Load() != 0
				}, 100*time.Millisecond, 10*time.Millisecond)
			}

			state, pending := taskState(tsk)
			require.Equal(t, tc.wantState, state)
			require.Equal(t, tc.wantEventPending, pending)
		})
	}
}

func TestExecutorReschedule(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		initialState State
		wantRun      bool
		wantState    State
	}{
		"scheduled task is executed": {
			initialState: StateScheduled,
			wantRun:      true,
			wantState:    StateIdle,
		},
		"idle task is ignored by run": {
			initialState: StateIdle,
			wantRun:      false,
			wantState:    StateIdle,
		},
		"running task is ignored by run": {
			initialState: StateRunning,
			wantRun:      false,
			wantState:    StateRunning,
		},
		"closed task is ignored by run": {
			initialState: StateClosed,
			wantRun:      false,
			wantState:    StateClosed,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			executor, err := NewExecutor(1)
			require.NoError(t, err)

			defer executor.Stop()

			var calls atomic.Int32

			tsk := &testTask{
				runFunc: func() {
					calls.Add(1)
				},
			}
			setTaskState(tsk, tc.initialState, false)

			executor.reschedule(tsk)

			if tc.wantRun {
				require.Eventually(t, func() bool {
					return calls.Load() == 1
				}, time.Second, 10*time.Millisecond)
			} else {
				require.Never(t, func() bool {
					return calls.Load() != 0
				}, 100*time.Millisecond, 10*time.Millisecond)
			}

			state, pending := taskState(tsk)
			require.Equal(t, tc.wantState, state)
			require.False(t, pending)
		})
	}
}

func TestExecutorRun(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		initialState     State
		setEventPending  bool
		wantCalls        int32
		wantFinalState   State
		wantFinalPending bool
	}{
		"scheduled task runs once": {
			initialState:   StateScheduled,
			wantCalls:      1,
			wantFinalState: StateIdle,
		},
		"non scheduled task is ignored": {
			initialState:   StateIdle,
			wantCalls:      0,
			wantFinalState: StateIdle,
		},
		"pending event is rescheduled": {
			initialState:    StateScheduled,
			setEventPending: true,
			wantCalls:       2,
			wantFinalState:  StateIdle,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			executor, err := NewExecutor(1)
			require.NoError(t, err)

			defer executor.Stop()

			var calls atomic.Int32

			tsk := &testTask{}
			tsk.runFunc = func() {
				call := calls.Add(1)

				if call == 1 && tc.setEventPending {
					tsk.stateMu.Lock()
					tsk.eventPending = true
					tsk.stateMu.Unlock()
				}
			}

			setTaskState(tsk, tc.initialState, false)

			executor.run(tsk)

			require.Eventually(t, func() bool {
				return calls.Load() == tc.wantCalls
			}, time.Second, 10*time.Millisecond)

			state, pending := taskState(tsk)
			require.Equal(t, tc.wantFinalState, state)
			require.Equal(t, tc.wantFinalPending, pending)
		})
	}
}

func TestExecutorDispatch(t *testing.T) {
	t.Parallel()

	t.Run("runs task payload", func(t *testing.T) {
		t.Parallel()

		executor, err := NewExecutor(1)
		require.NoError(t, err)

		defer executor.Stop()

		var calls atomic.Int32

		tsk := &testTask{
			runFunc: func() {
				calls.Add(1)
			},
		}
		setTaskState(tsk, StateScheduled, false)

		executor.dispatch(tsk)

		require.EqualValues(t, 1, calls.Load())

		state, pending := taskState(tsk)
		require.Equal(t, StateIdle, state)
		require.False(t, pending)
	})

	t.Run("ignores invalid payload", func(t *testing.T) {
		t.Parallel()

		executor, err := NewExecutor(1)
		require.NoError(t, err)

		defer executor.Stop()

		require.NotPanics(t, func() {
			executor.dispatch("not-a-task")
		})
	})
}

func TestExecutorScheduleInvokeError(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		operation    func(*Executor, *testTask)
		initialState State
	}{
		"schedule unschedules task when pool invoke fails": {
			operation: func(executor *Executor, tsk *testTask) {
				executor.Schedule(tsk)
			},
			initialState: StateIdle,
		},
		"reschedule unschedules task when pool invoke fails": {
			operation: func(executor *Executor, tsk *testTask) {
				executor.reschedule(tsk)
			},
			initialState: StateScheduled,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			executor, err := NewExecutor(1)
			require.NoError(t, err)

			executor.Stop()

			tsk := &testTask{}
			setTaskState(tsk, tc.initialState, true)

			tc.operation(executor, tsk)

			state, pending := taskState(tsk)
			require.Equal(t, StateIdle, state)
			require.False(t, pending)
			require.EqualValues(t, 1, tsk.unscheduleCalls.Load())

			reason, ok := tsk.unscheduleErr.Load().(error)
			require.True(t, ok)
			require.Error(t, reason)
		})
	}
}
