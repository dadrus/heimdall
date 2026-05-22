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
