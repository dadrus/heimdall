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

package ioprogress

import (
	"testing"
	"time"
)

func BenchmarkDeadlineTrackerNextDeadline(b *testing.B) {
	startedAt := time.Unix(1, 0)
	now := startedAt.Add(time.Second)

	for name, tc := range map[string]struct {
		hardTimeout time.Duration
		idleTimeout time.Duration
		minRate     int64
	}{
		"idle only": {
			idleTimeout: 30 * time.Second,
		},
		"idle and minimum rate": {
			idleTimeout: 30 * time.Second,
			minRate:     500,
		},
		"hard idle and minimum rate": {
			hardTimeout: 5 * time.Minute,
			idleTimeout: 30 * time.Second,
			minRate:     500,
		},
	} {
		b.Run(name, func(b *testing.B) {
			tracker := newDeadlineTracker(tc.hardTimeout, tc.idleTimeout, tc.minRate, startedAt)
			tracker.recordTransfer(64 * 1024)

			var deadline time.Time

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				deadline = tracker.nextDeadline(now)
			}

			if deadline.IsZero() {
				b.Fatal("expected deadline")
			}
		})
	}
}
