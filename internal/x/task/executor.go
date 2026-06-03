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

import (
	"github.com/panjf2000/ants/v2"
)

type Executor struct {
	pool *ants.PoolWithFunc
}

func NewExecutor(numberOfWorkers int) (*Executor, error) {
	exec := &Executor{}

	pool, err := ants.NewPoolWithFunc(
		numberOfWorkers,
		exec.dispatch,
	)
	if err != nil {
		return nil, err
	}

	exec.pool = pool

	return exec, nil
}

func (d *Executor) Schedule(tsk Task) {
	if !tsk.Schedule() {
		return
	}

	if err := d.pool.Invoke(tsk); err != nil {
		tsk.Unschedule(err)
	}
}

func (d *Executor) Stop() {
	d.pool.Release()
}

func (d *Executor) reschedule(tsk Task) {
	if err := d.pool.Invoke(tsk); err != nil {
		tsk.Unschedule(err)
	}
}

func (d *Executor) run(tsk Task) {
	if !tsk.BeginRun() {
		return
	}

	tsk.Run()

	if tsk.FinishRun() {
		d.reschedule(tsk)
	}
}

func (d *Executor) dispatch(payload any) {
	tsk, ok := payload.(Task)
	if !ok {
		return
	}

	d.run(tsk)
}
