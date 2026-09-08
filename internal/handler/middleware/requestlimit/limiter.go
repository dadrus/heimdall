package requestlimit

import "sync/atomic"

type Limiter struct {
	max    int64
	active atomic.Int64
}

func New(max int) *Limiter {
	return &Limiter{
		max: int64(max),
	}
}

func (l *Limiter) TryAcquire() bool {
	if l.max == 0 {
		return true
	}

	for {
		active := l.active.Load()
		if active >= l.max {
			return false
		}

		if l.active.CompareAndSwap(active, active+1) {
			return true
		}
	}
}

func (l *Limiter) Release() {
	if l.max != 0 {
		l.active.Add(-1)
	}
}
