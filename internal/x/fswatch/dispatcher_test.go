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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestEventDispatcherStartAndStop(t *testing.T) {
	t.Parallel()

	handler := NewEventHandlerMock(t)
	dispatcher := newEventDispatcher(handler, zerolog.Nop())

	require.NoError(t, dispatcher.Start())
	require.NotNil(t, dispatcher.executor)
	require.NotNil(t, dispatcher.stopCh)

	require.NoError(t, dispatcher.Stop())
	require.Nil(t, dispatcher.executor)

	require.NoError(t, dispatcher.Stop())
}

func TestEventDispatcherDispatchesEventsInOrder(t *testing.T) {
	t.Parallel()

	handler := NewEventHandlerMock(t)

	var (
		mu      sync.Mutex
		events  []Event
		handled = make(chan struct{}, 3)
	)

	handler.EXPECT().
		HandleEvent(mock.Anything).
		RunAndReturn(func(evt Event) error {
			mu.Lock()

			events = append(events, evt)
			mu.Unlock()

			handled <- struct{}{}

			return nil
		})

	dispatcher := newEventDispatcher(handler, zerolog.Nop())

	require.NoError(t, dispatcher.Start())

	defer func() {
		require.NoError(t, dispatcher.Stop())
	}()

	expected := []Event{
		{Path: "/tmp/one.yaml", Op: OpAdded},
		{Path: "/tmp/two.yaml", Op: OpChanged},
		{Path: "/tmp/three.yaml", Op: OpDeleted},
	}

	for _, evt := range expected {
		dispatcher.Enqueue(evt)
	}

	requireHandled(t, handled, len(expected))

	mu.Lock()

	actual := append([]Event(nil), events...)
	mu.Unlock()

	assert.Equal(t, expected, actual)
}

func TestEventDispatcherContinuesAfterHandlerError(t *testing.T) {
	t.Parallel()

	handler := NewEventHandlerMock(t)

	var (
		mu      sync.Mutex
		events  []Event
		handled = make(chan struct{}, 2)
	)

	expectedErr := errors.New("failed handling event")

	handler.EXPECT().
		HandleEvent(mock.Anything).
		RunAndReturn(func(evt Event) error {
			mu.Lock()

			events = append(events, evt)
			mu.Unlock()

			handled <- struct{}{}

			if evt.Path == "/tmp/one.yaml" {
				return expectedErr
			}

			return nil
		})

	dispatcher := newEventDispatcher(handler, zerolog.Nop())

	require.NoError(t, dispatcher.Start())

	defer func() {
		require.NoError(t, dispatcher.Stop())
	}()

	expected := []Event{
		{Path: "/tmp/one.yaml", Op: OpChanged},
		{Path: "/tmp/two.yaml", Op: OpChanged},
	}

	for _, evt := range expected {
		dispatcher.Enqueue(evt)
	}

	requireHandled(t, handled, len(expected))

	mu.Lock()

	actual := append([]Event(nil), events...)

	mu.Unlock()

	assert.Equal(t, expected, actual)
}

func TestEventDispatcherRunStopsWithoutDrainingQueue(t *testing.T) {
	t.Parallel()

	handler := NewEventHandlerMock(t)

	dispatcher := newEventDispatcher(handler, zerolog.Nop())
	dispatcher.stopCh = make(chan struct{})
	dispatcher.queue = []Event{
		{Path: "/tmp/one.yaml", Op: OpChanged},
	}

	close(dispatcher.stopCh)

	dispatcher.Run()
}

func TestEventDispatcherUnscheduleCancelsSchedule(t *testing.T) {
	t.Parallel()

	handler := NewEventHandlerMock(t)
	dispatcher := newEventDispatcher(handler, zerolog.Nop())

	require.True(t, dispatcher.Schedule())
	require.False(t, dispatcher.Schedule())

	dispatcher.Unschedule(errors.New("failed scheduling task"))

	require.True(t, dispatcher.Schedule())
}

func requireHandled(t *testing.T, handled <-chan struct{}, count int) {
	t.Helper()

	for range count {
		require.Eventually(t, func() bool {
			select {
			case <-handled:
				return true
			default:
				return false
			}
		}, time.Second, 10*time.Millisecond)
	}
}
