package secrets

import (
	"github.com/panjf2000/ants/v2"
	"github.com/rs/zerolog"
)

const subscriptionDispatchWorkers = 4

type dispatcher struct {
	logger zerolog.Logger
	pool   *ants.PoolWithFunc
}

func newDispatcher(logger zerolog.Logger) (*dispatcher, error) {
	dsp := &dispatcher{logger: logger}

	pool, err := ants.NewPoolWithFunc(
		subscriptionDispatchWorkers,
		dsp.dispatch,
	)
	if err != nil {
		return nil, err
	}

	dsp.pool = pool

	return dsp, nil
}

func (d *dispatcher) schedule(bdg *binding) {
	if !bdg.schedule() {
		return
	}

	if err := d.pool.Invoke(bdg); err != nil {
		bdg.unschedule()

		d.logger.Warn().
			Err(err).
			Str("_source", bdg.source).
			Str("_namespace", bdg.namespace).
			Str("_selector", bdg.selector).
			Msg("Failed scheduling secret update callback")
	}
}

func (d *dispatcher) reschedule(bdg *binding) {
	if err := d.pool.Invoke(bdg); err != nil {
		bdg.unschedule()

		d.logger.Warn().
			Err(err).
			Str("_source", bdg.source).
			Str("_namespace", bdg.namespace).
			Str("_selector", bdg.selector).
			Msg("Failed rescheduling secret update callback")
	}
}

func (d *dispatcher) run(bdg *binding) {
	if !bdg.beginRun() {
		return
	}

	bdg.runCallbacks()

	if bdg.finishRun() {
		d.reschedule(bdg)
	}
}

func (d *dispatcher) stop() {
	if d.pool != nil {
		d.pool.Release()
	}
}

func (d *dispatcher) dispatch(payload any) {
	bdg, ok := payload.(*binding)
	if !ok {
		d.logger.Error().Msg("Invalid secret update dispatch payload")

		return
	}

	d.run(bdg)
}
