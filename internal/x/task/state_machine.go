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

package task

import "sync"

type State uint8

const (
	StateIdle State = iota
	StateScheduled
	StateRunning
	StateClosed
)

type StateMachine struct {
	stateMu      sync.Mutex
	state        State
	eventPending bool

	wg sync.WaitGroup
}

func (s *StateMachine) Schedule() bool {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()

	if s.state == StateClosed {
		return false
	}

	s.eventPending = true

	switch s.state {
	case StateIdle:
		s.state = StateScheduled

		return true
	case StateScheduled, StateRunning:
		return false
	default:
		return false
	}
}

func (s *StateMachine) CancelSchedule() {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()

	if s.state == StateScheduled {
		s.state = StateIdle
		s.eventPending = false
	}
}

func (s *StateMachine) BeginRun() bool {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()

	if s.state != StateScheduled {
		return false
	}

	s.state = StateRunning
	s.eventPending = false
	s.wg.Add(1)

	return true
}

func (s *StateMachine) FinishRun() bool {
	defer s.wg.Done()

	s.stateMu.Lock()
	defer s.stateMu.Unlock()

	if s.state == StateClosed {
		return false
	}

	if s.eventPending {
		s.state = StateScheduled

		return true
	}

	s.state = StateIdle

	return false
}

func (s *StateMachine) Stop() {
	s.stateMu.Lock()
	s.state = StateClosed
	s.eventPending = false
	s.stateMu.Unlock()

	s.wg.Wait()
}
