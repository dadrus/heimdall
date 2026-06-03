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
	"sync"
	"time"

	"github.com/rs/zerolog"
)

type eventDispatcher struct {
	handler EventHandler
	logger  zerolog.Logger

	lifecycleMu sync.RWMutex
	started     bool

	stopCh   chan struct{}
	signalCh chan struct{}

	coalescer *eventCoalescer

	queueMu sync.Mutex
	queue   []Event

	wg sync.WaitGroup
}

func newEventDispatcher(
	handler EventHandler,
	logger zerolog.Logger,
	debounce time.Duration,
	maxDebounce time.Duration,
) *eventDispatcher {
	dsp := &eventDispatcher{
		handler:  handler,
		logger:   logger,
		stopCh:   make(chan struct{}),
		signalCh: make(chan struct{}, 1),
	}

	dsp.coalescer = newEventCoalescer(debounce, maxDebounce, dsp.enqueueReady, logger)

	return dsp
}

func (d *eventDispatcher) start() {
	d.lifecycleMu.Lock()
	defer d.lifecycleMu.Unlock()

	if d.started {
		return
	}

	d.started = true
	d.wg.Go(d.run)
}

func (d *eventDispatcher) stop() {
	d.lifecycleMu.Lock()

	if !d.started {
		d.lifecycleMu.Unlock()

		return
	}

	stopCh := d.stopCh
	d.started = false

	d.lifecycleMu.Unlock()

	d.coalescer.stop()

	close(stopCh)
	d.wg.Wait()

	d.queueMu.Lock()
	d.queue = nil
	d.queueMu.Unlock()
}

func (d *eventDispatcher) enqueue(evt Event) {
	d.lifecycleMu.RLock()
	started := d.started
	coalescer := d.coalescer
	d.lifecycleMu.RUnlock()

	if !started {
		return
	}

	coalescer.enqueue(evt)
}

func (d *eventDispatcher) remove(path string) {
	d.lifecycleMu.RLock()
	started := d.started
	coalescer := d.coalescer
	d.lifecycleMu.RUnlock()

	if started {
		coalescer.remove(path)
	}

	d.queueMu.Lock()
	defer d.queueMu.Unlock()

	kept := d.queue[:0]
	for _, evt := range d.queue {
		if evt.Path == path || isDirectChild(path, evt.Path) {
			continue
		}

		kept = append(kept, evt)
	}

	d.queue = kept
}

func (d *eventDispatcher) enqueueReady(evt Event) {
	d.lifecycleMu.RLock()

	if !d.started {
		d.lifecycleMu.RUnlock()

		return
	}

	signalCh := d.signalCh
	d.lifecycleMu.RUnlock()

	d.queueMu.Lock()
	d.queue = append(d.queue, evt)
	d.queueMu.Unlock()

	select {
	case signalCh <- struct{}{}:
	default:
	}
}

func (d *eventDispatcher) run() {
	stopCh := d.stopCh
	signalCh := d.signalCh

	for {
		select {
		case <-stopCh:
			return
		case <-signalCh:
			if !d.drain(stopCh) {
				return
			}
		}
	}
}

func (d *eventDispatcher) drain(stopCh <-chan struct{}) bool {
	for evt, ok := d.next(); ok; evt, ok = d.next() {
		select {
		case <-stopCh:
			return false
		default:
		}

		if err := d.handler.HandleEvent(evt); err != nil {
			d.logger.Error().
				Err(err).
				Str("_file", evt.Path).
				Str("_operation", evt.Op.String()).
				Msg("Failed handling file event")
		}
	}

	return true
}

func (d *eventDispatcher) next() (Event, bool) {
	d.queueMu.Lock()
	defer d.queueMu.Unlock()

	if len(d.queue) == 0 {
		return Event{}, false
	}

	evt := d.queue[0]

	copy(d.queue, d.queue[1:])
	d.queue = d.queue[:len(d.queue)-1]

	return evt, true
}
