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
	"sync"
	"time"

	"github.com/rs/zerolog"
)

type pendingEvent struct {
	event Event

	firstSeen time.Time
	due       time.Time

	timer *time.Timer
}

type eventCoalescer struct {
	debounce    time.Duration
	maxDebounce time.Duration
	dispatch    func(Event)
	logger      zerolog.Logger

	mu      sync.Mutex
	stopped bool
	pending map[string]*pendingEvent
}

func newEventCoalescer(
	debounce time.Duration,
	maxDebounce time.Duration,
	dispatch func(Event),
	logger zerolog.Logger,
) *eventCoalescer {
	return &eventCoalescer{
		debounce:    debounce,
		maxDebounce: maxDebounce,
		dispatch:    dispatch,
		logger:      logger,
		pending:     make(map[string]*pendingEvent),
	}
}

func (c *eventCoalescer) enqueue(evt Event) {
	if c.debounce <= 0 {
		c.dispatch(evt)

		return
	}

	now := time.Now()
	key := evt.Path

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.stopped {
		return
	}

	if pending, ok := c.pending[key]; ok {
		pending.event.Op = mergeOp(pending.event.Op, evt.Op)
		pending.due = c.nextDue(pending.firstSeen, now)
		pending.timer.Reset(time.Until(pending.due))

		c.logger.Debug().
			Str("_file", pending.event.Path).
			Str("_operation", pending.event.Op.String()).
			Msg("Coalesced file event")

		return
	}

	due := c.nextDue(now, now)
	pending := &pendingEvent{
		event:     evt,
		firstSeen: now,
		due:       due,
	}
	pending.timer = time.AfterFunc(time.Until(due), func() { c.flush(key) })
	c.pending[key] = pending
}

func (c *eventCoalescer) remove(path string) {
	if c.debounce <= 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for key, pending := range c.pending {
		if key == path || isDirectChild(path, key) {
			pending.timer.Stop()
			delete(c.pending, key)
		}
	}
}

func (c *eventCoalescer) stop() {
	if c.debounce <= 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.stopped = true

	for key, pending := range c.pending {
		pending.timer.Stop()
		delete(c.pending, key)
	}
}

func (c *eventCoalescer) flush(key string) {
	c.mu.Lock()

	pending, ok := c.pending[key]
	if !ok || c.stopped {
		c.mu.Unlock()

		return
	}

	if wait := time.Until(pending.due); wait > 0 {
		pending.timer.Reset(wait)
		c.mu.Unlock()

		return
	}

	delete(c.pending, key)
	evt := pending.event

	c.mu.Unlock()

	c.logger.Debug().
		Str("_file", evt.Path).
		Str("_operation", evt.Op.String()).
		Msg("Dispatching coalesced file event")

	c.dispatch(evt)
}

func (c *eventCoalescer) nextDue(firstSeen, now time.Time) time.Time {
	due := now.Add(c.debounce)
	if c.maxDebounce <= 0 {
		return due
	}

	maxDue := firstSeen.Add(c.maxDebounce)
	if due.After(maxDue) {
		return maxDue
	}

	return due
}

func mergeOp(current, next Op) Op {
	if current == next {
		return current
	}

	if current == OpDeleted && next == OpAdded {
		return OpChanged
	}

	if next == OpDeleted {
		return OpDeleted
	}

	if current == OpDeleted {
		return OpDeleted
	}

	if current == OpAdded || next == OpAdded {
		return OpAdded
	}

	return OpChanged
}
