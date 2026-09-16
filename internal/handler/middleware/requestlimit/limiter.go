// Copyright 2026 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

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
