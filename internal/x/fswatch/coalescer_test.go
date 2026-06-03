// Copyright 2026 Dimitrij Drus
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
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
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMergeOp(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		current Op
		next    Op
		want    Op
	}{
		"changed":         {current: OpChanged, next: OpChanged, want: OpChanged},
		"added changed":   {current: OpAdded, next: OpChanged, want: OpAdded},
		"changed added":   {current: OpChanged, next: OpAdded, want: OpAdded},
		"changed deleted": {current: OpChanged, next: OpDeleted, want: OpDeleted},
		"added deleted":   {current: OpAdded, next: OpDeleted, want: OpDeleted},
		"deleted added":   {current: OpDeleted, next: OpAdded, want: OpChanged},
		"deleted changed": {current: OpDeleted, next: OpChanged, want: OpDeleted},
		"unknown":         {current: Op(42), next: Op(43), want: OpChanged},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, mergeOp(tc.current, tc.next))
		})
	}
}

func TestEventCoalescer(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		debounce    time.Duration
		maxDebounce time.Duration
		enqueue     func(*eventCoalescer)
		assert      func(*testing.T, <-chan Event)
	}{
		"coalesces same path events": {
			debounce:    20 * time.Millisecond,
			maxDebounce: time.Second,
			enqueue: func(coalescer *eventCoalescer) {
				coalescer.enqueue(Event{Path: "/tmp/one.yaml", Op: OpChanged})
				coalescer.enqueue(Event{Path: "/tmp/one.yaml", Op: OpChanged})
			},
			assert: func(t *testing.T, events <-chan Event) {
				t.Helper()

				require.Eventually(t, func() bool {
					select {
					case evt := <-events:
						return evt == (Event{Path: "/tmp/one.yaml", Op: OpChanged})
					default:
						return false
					}
				}, time.Second, 10*time.Millisecond)

				require.Never(t, func() bool {
					select {
					case <-events:
						return true
					default:
						return false
					}
				}, 50*time.Millisecond, 10*time.Millisecond)
			},
		},
		"keeps different paths separate": {
			debounce:    20 * time.Millisecond,
			maxDebounce: time.Second,
			enqueue: func(coalescer *eventCoalescer) {
				coalescer.enqueue(Event{Path: "/tmp/one.yaml", Op: OpChanged})
				coalescer.enqueue(Event{Path: "/tmp/two.yaml", Op: OpChanged})
			},
			assert: func(t *testing.T, events <-chan Event) {
				t.Helper()

				received := make(map[Event]struct{})

				for range 2 {
					require.Eventually(t, func() bool {
						select {
						case evt := <-events:
							received[evt] = struct{}{}

							return true
						default:
							return false
						}
					}, time.Second, 10*time.Millisecond)
				}

				assert.Contains(t, received, Event{Path: "/tmp/one.yaml", Op: OpChanged})
				assert.Contains(t, received, Event{Path: "/tmp/two.yaml", Op: OpChanged})
			},
		},
		"emits outside debounce window separately": {
			debounce:    20 * time.Millisecond,
			maxDebounce: time.Second,
			enqueue: func(coalescer *eventCoalescer) {
				coalescer.enqueue(Event{Path: "/tmp/one.yaml", Op: OpChanged})
				time.Sleep(40 * time.Millisecond)
				coalescer.enqueue(Event{Path: "/tmp/one.yaml", Op: OpChanged})
			},
			assert: func(t *testing.T, events <-chan Event) {
				t.Helper()

				for range 2 {
					require.Eventually(t, func() bool {
						select {
						case evt := <-events:
							return evt == (Event{Path: "/tmp/one.yaml", Op: OpChanged})
						default:
							return false
						}
					}, time.Second, 10*time.Millisecond)
				}
			},
		},
		"can be disabled": {
			debounce: 0,
			enqueue: func(coalescer *eventCoalescer) {
				coalescer.enqueue(Event{Path: "/tmp/one.yaml", Op: OpChanged})
				coalescer.enqueue(Event{Path: "/tmp/one.yaml", Op: OpChanged})
			},
			assert: func(t *testing.T, events <-chan Event) {
				t.Helper()

				for range 2 {
					require.Eventually(t, func() bool {
						select {
						case evt := <-events:
							return evt == (Event{Path: "/tmp/one.yaml", Op: OpChanged})
						default:
							return false
						}
					}, time.Second, 10*time.Millisecond)
				}
			},
		},
		"flushes no later than max debounce": {
			debounce:    100 * time.Millisecond,
			maxDebounce: 40 * time.Millisecond,
			enqueue: func(coalescer *eventCoalescer) {
				coalescer.enqueue(Event{Path: "/tmp/one.yaml", Op: OpChanged})
				time.Sleep(20 * time.Millisecond)
				coalescer.enqueue(Event{Path: "/tmp/one.yaml", Op: OpChanged})
				time.Sleep(20 * time.Millisecond)
				coalescer.enqueue(Event{Path: "/tmp/one.yaml", Op: OpChanged})
			},
			assert: func(t *testing.T, events <-chan Event) {
				t.Helper()

				require.Eventually(t, func() bool {
					select {
					case evt := <-events:
						return evt == (Event{Path: "/tmp/one.yaml", Op: OpChanged})
					default:
						return false
					}
				}, 80*time.Millisecond, 10*time.Millisecond)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			events := make(chan Event, 4)
			coalescer := newEventCoalescer(
				tc.debounce,
				tc.maxDebounce,
				func(evt Event) { events <- evt },
				zerolog.Nop(),
			)
			t.Cleanup(coalescer.stop)

			tc.enqueue(coalescer)
			tc.assert(t, events)
		})
	}
}

func TestEventCoalescerMergeOperations(t *testing.T) {
	t.Parallel()

	events := make(chan Event, 1)
	coalescer := newEventCoalescer(
		20*time.Millisecond,
		time.Second,
		func(evt Event) { events <- evt },
		zerolog.Nop(),
	)
	t.Cleanup(coalescer.stop)

	coalescer.enqueue(Event{Path: "/tmp/one.yaml", Op: OpAdded})
	coalescer.enqueue(Event{Path: "/tmp/one.yaml", Op: OpChanged})

	require.Eventually(t, func() bool {
		select {
		case evt := <-events:
			return evt == (Event{Path: "/tmp/one.yaml", Op: OpAdded})
		default:
			return false
		}
	}, time.Second, 10*time.Millisecond)
}

func TestEventCoalescerRemove(t *testing.T) {
	t.Parallel()

	unexpected := make(chan Event, 1)
	coalescer := newEventCoalescer(
		20*time.Millisecond,
		time.Second,
		func(evt Event) { unexpected <- evt },
		zerolog.Nop(),
	)
	t.Cleanup(coalescer.stop)

	coalescer.enqueue(Event{Path: "/tmp/one.yaml", Op: OpChanged})
	coalescer.remove("/tmp/one.yaml")

	require.Never(t, func() bool {
		select {
		case <-unexpected:
			return true
		default:
			return false
		}
	}, 50*time.Millisecond, 10*time.Millisecond)
}

func TestEventCoalescerRemoveReturnsWhenDisabled(t *testing.T) {
	t.Parallel()

	events := make(chan Event, 1)
	coalescer := newEventCoalescer(
		0,
		time.Second,
		func(evt Event) { events <- evt },
		zerolog.Nop(),
	)

	expected := Event{Path: "/tmp/one.yaml", Op: OpChanged}

	coalescer.enqueue(expected)
	coalescer.remove(expected.Path)

	require.Eventually(t, func() bool {
		select {
		case evt := <-events:
			return assert.Equal(t, expected, evt)
		default:
			return false
		}
	}, time.Second, 10*time.Millisecond)
}

func TestEventCoalescerFlushIgnoresUnknownKey(t *testing.T) {
	t.Parallel()

	events := make(chan Event, 1)
	coalescer := newEventCoalescer(
		20*time.Millisecond,
		time.Second,
		func(evt Event) { events <- evt },
		zerolog.Nop(),
	)
	t.Cleanup(coalescer.stop)

	coalescer.flush("/tmp/missing.yaml")

	require.Never(t, func() bool {
		return len(events) > 0
	}, 50*time.Millisecond, 10*time.Millisecond)
}

func TestEventCoalescerFlushIgnoresStoppedCoalescer(t *testing.T) {
	t.Parallel()

	events := make(chan Event, 1)
	coalescer := newEventCoalescer(
		time.Second,
		time.Second,
		func(evt Event) { events <- evt },
		zerolog.Nop(),
	)

	coalescer.enqueue(Event{Path: "/tmp/one.yaml", Op: OpChanged})

	coalescer.mu.Lock()
	require.Contains(t, coalescer.pending, "/tmp/one.yaml")
	coalescer.mu.Unlock()

	coalescer.stop()
	coalescer.flush("/tmp/one.yaml")

	require.Never(t, func() bool {
		return len(events) > 0
	}, 50*time.Millisecond, 10*time.Millisecond)
}

func TestEventCoalescerStopDropsPendingEvents(t *testing.T) {
	t.Parallel()

	events := make(chan Event, 1)
	coalescer := newEventCoalescer(
		20*time.Millisecond,
		time.Second,
		func(evt Event) { events <- evt },
		zerolog.Nop(),
	)

	coalescer.enqueue(Event{Path: "/tmp/one.yaml", Op: OpChanged})
	coalescer.stop()

	require.Never(t, func() bool {
		return len(events) > 0
	}, 50*time.Millisecond, 10*time.Millisecond)
}

func TestEventCoalescerFlushResetsTimerWhenEventIsNotDue(t *testing.T) {
	t.Parallel()

	events := make(chan Event, 1)
	coalescer := newEventCoalescer(
		100*time.Millisecond,
		time.Second,
		func(evt Event) { events <- evt },
		zerolog.Nop(),
	)
	t.Cleanup(coalescer.stop)

	expected := Event{Path: "/tmp/one.yaml", Op: OpChanged}

	coalescer.enqueue(expected)
	coalescer.flush(expected.Path)

	require.Never(t, func() bool {
		return len(events) > 0
	}, 50*time.Millisecond, 10*time.Millisecond)

	require.Eventually(t, func() bool {
		select {
		case evt := <-events:
			return assert.Equal(t, expected, evt)
		default:
			return false
		}
	}, time.Second, 10*time.Millisecond)
}

func TestEventCoalescerNextDue(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.June, 3, 10, 0, 0, 0, time.UTC)

	for uc, tc := range map[string]struct {
		debounce    time.Duration
		maxDebounce time.Duration
		firstSeen   time.Time
		now         time.Time
		want        time.Time
	}{
		"without max debounce": {
			debounce:    50 * time.Millisecond,
			maxDebounce: 0,
			firstSeen:   now,
			now:         now.Add(200 * time.Millisecond),
			want:        now.Add(250 * time.Millisecond),
		},
		"before max debounce": {
			debounce:    50 * time.Millisecond,
			maxDebounce: time.Second,
			firstSeen:   now,
			now:         now.Add(100 * time.Millisecond),
			want:        now.Add(150 * time.Millisecond),
		},
		"capped by max debounce": {
			debounce:    100 * time.Millisecond,
			maxDebounce: 150 * time.Millisecond,
			firstSeen:   now,
			now:         now.Add(100 * time.Millisecond),
			want:        now.Add(150 * time.Millisecond),
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			coalescer := newEventCoalescer(
				tc.debounce,
				tc.maxDebounce,
				func(Event) {},
				zerolog.Nop(),
			)

			assert.Equal(t, tc.want, coalescer.nextDue(tc.firstSeen, tc.now))
		})
	}
}
