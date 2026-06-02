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

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/x/task"
)

type eventDispatcher struct {
	task.StateMachine

	handler  EventHandler
	executor *task.Executor
	logger   zerolog.Logger
	stopCh   chan struct{}

	queueMu sync.Mutex
	queue   []Event
}

func newEventDispatcher(handler EventHandler, logger zerolog.Logger) *eventDispatcher {
	return &eventDispatcher{
		handler: handler,
		logger:  logger,
	}
}

func (d *eventDispatcher) Start() error {
	executor, err := task.NewExecutor(1)
	if err != nil {
		return err
	}

	d.executor = executor
	d.stopCh = make(chan struct{})

	return nil
}

func (d *eventDispatcher) Stop() error {
	if d.executor == nil {
		return nil
	}

	close(d.stopCh)

	d.executor.Stop()
	d.executor = nil

	return nil
}

func (d *eventDispatcher) Enqueue(evt Event) {
	d.queueMu.Lock()
	d.queue = append(d.queue, evt)
	d.queueMu.Unlock()

	d.executor.Schedule(d)
}

func (d *eventDispatcher) Unschedule(reason error) {
	d.CancelSchedule()

	d.logger.Error().
		Err(reason).
		Msg("Failed scheduling file event dispatch")
}

func (d *eventDispatcher) Run() {
	for {
		select {
		case <-d.stopCh:
			return
		default:
		}

		evt, ok := d.next()
		if !ok {
			return
		}

		if err := d.handler.HandleEvent(evt); err != nil {
			d.logger.Error().
				Err(err).
				Str("_file", evt.Path).
				Str("_operation", evt.Op.String()).
				Msg("Failed handling file event")
		}
	}
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
