// Copyright 2026 Dimitrij Drus
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package fswatch

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestEventDispatcherDispatchesQueuedEvents(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		events []Event
	}{
		"single event": {
			events: []Event{
				{Path: "/tmp/one.pem", Op: OpChanged},
			},
		},
		"multiple events": {
			events: []Event{
				{Path: "/tmp/one.pem", Op: OpChanged},
				{Path: "/tmp/two.pem", Op: OpAdded},
				{Path: "/tmp/three.pem", Op: OpDeleted},
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var (
				mu       sync.Mutex
				received []Event
			)

			dispatcher := newEventDispatcher(
				EventHandlerFunc(func(evt Event) error {
					mu.Lock()
					defer mu.Unlock()

					received = append(received, evt)

					return nil
				}),
				zerolog.Nop(),
				0,
				0,
			)

			dispatcher.start()
			t.Cleanup(dispatcher.stop)

			for _, evt := range tc.events {
				dispatcher.enqueue(evt)
			}

			require.Eventually(t, func() bool {
				mu.Lock()
				defer mu.Unlock()

				return len(received) == len(tc.events)
			}, time.Second, 10*time.Millisecond)

			mu.Lock()
			defer mu.Unlock()

			require.Equal(t, tc.events, received)
		})
	}
}

func TestEventDispatcherDoesNotDispatchBeforeStart(t *testing.T) {
	t.Parallel()

	handled := make(chan Event, 1)

	dispatcher := newEventDispatcher(
		EventHandlerFunc(func(evt Event) error {
			handled <- evt

			return nil
		}),
		zerolog.Nop(),
		0,
		0,
	)

	dispatcher.enqueue(Event{Path: "/tmp/one.pem", Op: OpChanged})

	require.Never(t, func() bool {
		return len(handled) > 0
	}, 100*time.Millisecond, 10*time.Millisecond)
}

func TestEventDispatcherDoesNotDispatchAfterStop(t *testing.T) {
	t.Parallel()

	handled := make(chan Event, 1)

	dispatcher := newEventDispatcher(
		EventHandlerFunc(func(evt Event) error {
			handled <- evt

			return nil
		}),
		zerolog.Nop(),
		0,
		0,
	)

	dispatcher.start()
	dispatcher.stop()

	dispatcher.enqueue(Event{Path: "/tmp/one.pem", Op: OpChanged})

	require.Never(t, func() bool {
		return len(handled) > 0
	}, 100*time.Millisecond, 10*time.Millisecond)
}

func TestEventDispatcherCoalescesEvents(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		events []Event
		want   Event
	}{
		"duplicate changed events": {
			events: []Event{
				{Path: "/tmp/one.pem", Op: OpChanged},
				{Path: "/tmp/one.pem", Op: OpChanged},
			},
			want: Event{Path: "/tmp/one.pem", Op: OpChanged},
		},
		"added and changed events": {
			events: []Event{
				{Path: "/tmp/one.pem", Op: OpAdded},
				{Path: "/tmp/one.pem", Op: OpChanged},
			},
			want: Event{Path: "/tmp/one.pem", Op: OpAdded},
		},
		"deleted and added events": {
			events: []Event{
				{Path: "/tmp/one.pem", Op: OpDeleted},
				{Path: "/tmp/one.pem", Op: OpAdded},
			},
			want: Event{Path: "/tmp/one.pem", Op: OpChanged},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			handled := make(chan Event, len(tc.events))

			dispatcher := newEventDispatcher(
				EventHandlerFunc(func(evt Event) error {
					handled <- evt

					return nil
				}),
				zerolog.Nop(),
				20*time.Millisecond,
				time.Second,
			)

			dispatcher.start()
			t.Cleanup(dispatcher.stop)

			for _, evt := range tc.events {
				dispatcher.enqueue(evt)
			}

			require.Eventually(t, func() bool {
				return len(handled) == 1
			}, time.Second, 10*time.Millisecond)

			require.Equal(t, tc.want, <-handled)

			require.Never(t, func() bool {
				return len(handled) > 0
			}, 100*time.Millisecond, 10*time.Millisecond)
		})
	}
}

func TestEventDispatcherRemoveDropsPendingCoalescedEvents(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		removePath string
		event      Event
	}{
		"same path": {
			removePath: "/tmp/one.pem",
			event:      Event{Path: "/tmp/one.pem", Op: OpChanged},
		},
		"direct child": {
			removePath: "/tmp",
			event:      Event{Path: "/tmp/one.pem", Op: OpChanged},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			handled := make(chan Event, 1)

			dispatcher := newEventDispatcher(
				EventHandlerFunc(func(evt Event) error {
					handled <- evt

					return nil
				}),
				zerolog.Nop(),
				100*time.Millisecond,
				time.Second,
			)

			dispatcher.start()
			t.Cleanup(dispatcher.stop)

			dispatcher.enqueue(tc.event)
			dispatcher.remove(tc.removePath)

			require.Never(t, func() bool {
				return len(handled) > 0
			}, 200*time.Millisecond, 10*time.Millisecond)
		})
	}
}

func TestEventDispatcherRemoveKeepsUnrelatedEvents(t *testing.T) {
	t.Parallel()

	handled := make(chan Event, 1)

	dispatcher := newEventDispatcher(
		EventHandlerFunc(func(evt Event) error {
			handled <- evt

			return nil
		}),
		zerolog.Nop(),
		100*time.Millisecond,
		time.Second,
	)

	dispatcher.start()
	t.Cleanup(dispatcher.stop)

	want := Event{Path: "/tmp/other.pem", Op: OpChanged}

	dispatcher.enqueue(Event{Path: "/tmp/one.pem", Op: OpChanged})
	dispatcher.enqueue(want)
	dispatcher.remove("/tmp/one.pem")

	require.Eventually(t, func() bool {
		return len(handled) == 1
	}, time.Second, 10*time.Millisecond)

	require.Equal(t, want, <-handled)
}

func TestEventDispatcherContinuesAfterHandlerError(t *testing.T) {
	t.Parallel()

	expectedErr := errors.New("handler failed")

	var (
		mu       sync.Mutex
		received []Event
	)

	dispatcher := newEventDispatcher(
		EventHandlerFunc(func(evt Event) error {
			mu.Lock()
			defer mu.Unlock()

			received = append(received, evt)

			if len(received) == 1 {
				return expectedErr
			}

			return nil
		}),
		zerolog.Nop(),
		0,
		0,
	)

	dispatcher.start()
	t.Cleanup(dispatcher.stop)

	events := []Event{
		{Path: "/tmp/one.pem", Op: OpChanged},
		{Path: "/tmp/two.pem", Op: OpChanged},
	}

	for _, evt := range events {
		dispatcher.enqueue(evt)
	}

	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()

		return len(received) == len(events)
	}, time.Second, 10*time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	require.Equal(t, events, received)
}

func TestEventDispatcherHandlesEventsSerially(t *testing.T) {
	t.Parallel()

	var (
		mu      sync.Mutex
		running bool
		calls   int
	)

	dispatcher := newEventDispatcher(
		EventHandlerFunc(func(evt Event) error {
			mu.Lock()
			require.False(t, running)
			running = true
			calls++
			mu.Unlock()

			time.Sleep(10 * time.Millisecond)

			mu.Lock()
			running = false
			mu.Unlock()

			return nil
		}),
		zerolog.Nop(),
		0,
		0,
	)

	dispatcher.start()
	t.Cleanup(dispatcher.stop)

	for _, evt := range []Event{
		{Path: "/tmp/one.pem", Op: OpChanged},
		{Path: "/tmp/two.pem", Op: OpChanged},
		{Path: "/tmp/three.pem", Op: OpChanged},
	} {
		dispatcher.enqueue(evt)
	}

	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()

		return calls == 3
	}, time.Second, 10*time.Millisecond)
}

func TestEventDispatcherStopWaitsForRunningHandler(t *testing.T) {
	t.Parallel()

	handlerEntered := make(chan struct{})
	releaseHandler := make(chan struct{})
	handlerDone := make(chan struct{})

	dispatcher := newEventDispatcher(
		EventHandlerFunc(func(evt Event) error {
			close(handlerEntered)
			<-releaseHandler
			close(handlerDone)

			return nil
		}),
		zerolog.Nop(),
		0,
		0,
	)

	dispatcher.start()

	dispatcher.enqueue(Event{Path: "/tmp/one.pem", Op: OpChanged})

	require.Eventually(t, func() bool {
		select {
		case <-handlerEntered:
			return true
		default:
			return false
		}
	}, time.Second, 10*time.Millisecond)

	stopDone := make(chan struct{})

	go func() {
		dispatcher.stop()
		close(stopDone)
	}()

	require.Never(t, func() bool {
		select {
		case <-stopDone:
			return true
		default:
			return false
		}
	}, 100*time.Millisecond, 10*time.Millisecond)

	close(releaseHandler)

	require.Eventually(t, func() bool {
		select {
		case <-handlerDone:
		default:
		}

		select {
		case <-stopDone:
			return true
		default:
			return false
		}
	}, time.Second, 10*time.Millisecond)
}

func TestEventDispatcherRemoveFiltersQueuedEvents(t *testing.T) {
	t.Parallel()

	blockHandler := make(chan struct{})
	handlerEntered := make(chan struct{})
	handled := make(chan Event, 4)

	dispatcher := newEventDispatcher(
		EventHandlerFunc(func(evt Event) error {
			handled <- evt

			if evt.Path == "/tmp/blocking.pem" {
				close(handlerEntered)
				<-blockHandler
			}

			return nil
		}),
		zerolog.Nop(),
		0,
		0,
	)

	dispatcher.start()
	t.Cleanup(dispatcher.stop)

	dispatcher.enqueue(Event{Path: "/tmp/blocking.pem", Op: OpChanged})

	require.Eventually(t, func() bool {
		select {
		case <-handlerEntered:
			return true
		default:
			return false
		}
	}, time.Second, 10*time.Millisecond)

	removed := Event{Path: "/tmp/remove.pem", Op: OpChanged}
	kept := Event{Path: "/tmp/keep.pem", Op: OpChanged}

	dispatcher.enqueue(removed)
	dispatcher.enqueue(kept)

	require.Eventually(t, func() bool {
		dispatcher.queueMu.Lock()
		defer dispatcher.queueMu.Unlock()

		return len(dispatcher.queue) == 2
	}, time.Second, 10*time.Millisecond)

	dispatcher.remove(removed.Path)

	dispatcher.queueMu.Lock()
	require.Equal(t, []Event{kept}, dispatcher.queue)
	dispatcher.queueMu.Unlock()

	close(blockHandler)

	require.Eventually(t, func() bool {
		return len(handled) == 2
	}, time.Second, 10*time.Millisecond)

	require.Equal(t, Event{Path: "/tmp/blocking.pem", Op: OpChanged}, <-handled)
	require.Equal(t, kept, <-handled)

	require.Never(t, func() bool {
		return len(handled) > 0
	}, 100*time.Millisecond, 10*time.Millisecond)
}

func TestEventDispatcherRemoveFiltersQueuedChildEvents(t *testing.T) {
	t.Parallel()

	blockHandler := make(chan struct{})
	handlerEntered := make(chan struct{})
	handled := make(chan Event, 4)

	dispatcher := newEventDispatcher(
		EventHandlerFunc(func(evt Event) error {
			handled <- evt

			if evt.Path == "/tmp/blocking.pem" {
				close(handlerEntered)
				<-blockHandler
			}

			return nil
		}),
		zerolog.Nop(),
		0,
		0,
	)

	dispatcher.start()
	t.Cleanup(dispatcher.stop)

	dispatcher.enqueue(Event{Path: "/tmp/blocking.pem", Op: OpChanged})

	require.Eventually(t, func() bool {
		select {
		case <-handlerEntered:
			return true
		default:
			return false
		}
	}, time.Second, 10*time.Millisecond)

	child := Event{Path: "/tmp/secrets/tls.pem", Op: OpChanged}
	nested := Event{Path: "/tmp/secrets/nested/tls.pem", Op: OpChanged}
	kept := Event{Path: "/tmp/other/tls.pem", Op: OpChanged}

	dispatcher.enqueue(child)
	dispatcher.enqueue(nested)
	dispatcher.enqueue(kept)

	require.Eventually(t, func() bool {
		dispatcher.queueMu.Lock()
		defer dispatcher.queueMu.Unlock()

		return len(dispatcher.queue) == 3
	}, time.Second, 10*time.Millisecond)

	dispatcher.remove("/tmp/secrets")

	dispatcher.queueMu.Lock()
	require.Equal(t, []Event{nested, kept}, dispatcher.queue)
	dispatcher.queueMu.Unlock()

	close(blockHandler)

	require.Eventually(t, func() bool {
		return len(handled) == 3
	}, time.Second, 10*time.Millisecond)

	require.Equal(t, Event{Path: "/tmp/blocking.pem", Op: OpChanged}, <-handled)
	require.Equal(t, nested, <-handled)
	require.Equal(t, kept, <-handled)
}

func TestEventDispatcherRunReturnsWhenDrainObservesStop(t *testing.T) {
	t.Parallel()

	handlerEntered := make(chan struct{})
	releaseHandler := make(chan struct{})
	stopStarted := make(chan struct{})
	stopDone := make(chan struct{})
	handled := make(chan Event, 2)

	dispatcher := newEventDispatcher(
		EventHandlerFunc(func(evt Event) error {
			handled <- evt

			if evt.Path == "/tmp/blocking.pem" {
				close(handlerEntered)
				<-releaseHandler
			}

			return nil
		}),
		zerolog.Nop(),
		0,
		0,
	)

	dispatcher.start()

	dispatcher.enqueue(Event{Path: "/tmp/blocking.pem", Op: OpChanged})

	require.Eventually(t, func() bool {
		select {
		case <-handlerEntered:
			return true
		default:
			return false
		}
	}, time.Second, 10*time.Millisecond)

	dispatcher.enqueue(Event{Path: "/tmp/queued.pem", Op: OpChanged})

	go func() {
		close(stopStarted)
		dispatcher.stop()
		close(stopDone)
	}()

	require.Eventually(t, func() bool {
		select {
		case <-stopStarted:
			return true
		default:
			return false
		}
	}, time.Second, 10*time.Millisecond)

	require.Never(t, func() bool {
		select {
		case <-stopDone:
			return true
		default:
			return false
		}
	}, 100*time.Millisecond, 10*time.Millisecond)

	close(releaseHandler)

	require.Eventually(t, func() bool {
		select {
		case <-stopDone:
			return true
		default:
			return false
		}
	}, time.Second, 10*time.Millisecond)

	require.Equal(t, Event{Path: "/tmp/blocking.pem", Op: OpChanged}, <-handled)

	require.Never(t, func() bool {
		return len(handled) > 0
	}, 100*time.Millisecond, 10*time.Millisecond)
}
