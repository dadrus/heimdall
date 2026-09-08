package requestlimit

import "sync/atomic"

type Limiter struct {
	limit  int64
	active atomic.Int64
}

func New(limit int64) *Limiter {
	return &Limiter{
		limit: limit,
	}
}

func (l *Limiter) TryAcquire() bool {
	if l.limit == 0 {
		return true
	}

	for {
		active := l.active.Load()
		if active >= l.limit {
			return false
		}

		if l.active.CompareAndSwap(active, active+1) {
			return true
		}
	}
}

func (l *Limiter) Release() {
	if l.limit != 0 {
		l.active.Add(-1)
	}
}
