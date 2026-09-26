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
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeadlineTrackerNextDeadline(t *testing.T) {
	t.Parallel()

	startedAt := time.Date(2026, time.September, 12, 0, 0, 0, 0, time.UTC)
	now := startedAt.Add(10 * time.Second)

	for uc, tc := range map[string]struct {
		hardTimeout    time.Duration
		idleTimeout    time.Duration
		minRate        int64
		recordTransfer func(*deadlineTracker)
		expect         time.Time
	}{
		"disabled limits return zero deadline": {},
		"hard timeout remains anchored at phase start": {
			hardTimeout: time.Minute,
			expect:      startedAt.Add(time.Minute),
		},
		"idle timeout is a sliding window": {
			idleTimeout: 5 * time.Second,
			expect:      now.Add(5 * time.Second),
		},
		"hard timeout caps sliding idle window": {
			hardTimeout: 12 * time.Second,
			idleTimeout: 5 * time.Second,
			expect:      startedAt.Add(12 * time.Second),
		},
		"minimum rate starts from fixed phase start with idle allowance": {
			idleTimeout: 4 * time.Second,
			minRate:     100,
			expect:      startedAt.Add(4 * time.Second),
		},
		"transferred bytes add wall clock credit": {
			idleTimeout: 4 * time.Second,
			minRate:     100,
			recordTransfer: func(tracker *deadlineTracker) {
				tracker.recordTransfer(300)
			},
			expect: startedAt.Add(7 * time.Second),
		},
		"minimum rate credit can extend beyond a sliding idle window": {
			idleTimeout: 4 * time.Second,
			minRate:     100,
			recordTransfer: func(tracker *deadlineTracker) {
				tracker.recordTransfer(2_000)
			},
			expect: startedAt.Add(24 * time.Second),
		},
		"hard timeout caps accumulated minimum rate credit": {
			hardTimeout: 6 * time.Second,
			idleTimeout: 4 * time.Second,
			minRate:     100,
			recordTransfer: func(tracker *deadlineTracker) {
				tracker.recordTransfer(10_000)
			},
			expect: startedAt.Add(6 * time.Second),
		},
		"minimum rate deadline saturates on excessive byte credit": {
			idleTimeout: time.Second,
			minRate:     1,
			recordTransfer: func(tracker *deadlineTracker) {
				tracker.transferredBytes = math.MaxUint64
			},
			expect: startedAt.Add(time.Duration(math.MaxInt64)),
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			// GIVEN
			tracker := newDeadlineTracker(tc.hardTimeout, tc.idleTimeout, tc.minRate, startedAt)
			if tc.recordTransfer != nil {
				tc.recordTransfer(&tracker)
			}

			// WHEN
			deadline := tracker.nextDeadline(now)

			// THEN
			assert.Equal(t, tc.expect, deadline)
		})
	}

	t.Run("minimum rate uses wall clock instead of sliding idle window", func(t *testing.T) {
		t.Parallel()

		// GIVEN
		idleOnly := newDeadlineTracker(0, 4*time.Second, 0, startedAt)
		withMinimumRate := newDeadlineTracker(0, 4*time.Second, 100, startedAt)
		withMinimumRate.recordTransfer(300)

		beforePause := startedAt.Add(2 * time.Second)
		afterPause := startedAt.Add(10 * time.Minute)

		// WHEN
		idleBeforePause := idleOnly.nextDeadline(beforePause)
		idleAfterPause := idleOnly.nextDeadline(afterPause)
		rateBeforePause := withMinimumRate.nextDeadline(beforePause)
		rateAfterPause := withMinimumRate.nextDeadline(afterPause)

		// THEN
		assert.Equal(t, beforePause.Add(4*time.Second), idleBeforePause)
		assert.Equal(t, afterPause.Add(4*time.Second), idleAfterPause)
		assert.Equal(t, startedAt.Add(7*time.Second), rateBeforePause)
		assert.Equal(t, rateBeforePause, rateAfterPause)
	})

	t.Run("hard deadline", func(t *testing.T) {
		t.Parallel()

		t.Run("without hard timeout", func(t *testing.T) {
			t.Parallel()

			tracker := newDeadlineTracker(0, time.Second, 0, startedAt)

			assert.True(t, tracker.hardDeadline().IsZero())
		})

		t.Run("with hard timeout", func(t *testing.T) {
			t.Parallel()

			tracker := newDeadlineTracker(time.Minute, time.Second, 0, startedAt)

			assert.Equal(t, startedAt.Add(time.Minute), tracker.hardDeadline())
		})
	})
}

func TestDeadlineTrackerRecordTransferSaturates(t *testing.T) {
	t.Parallel()

	// GIVEN
	tracker := &deadlineTracker{transferredBytes: math.MaxUint64 - 1}

	// WHEN
	tracker.recordTransfer(2)

	// THEN
	assert.Equal(t, uint64(math.MaxUint64), tracker.transferredBytes)
}

func TestBytesToDuration(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		transferred uint64
		rate        int64
		expect      time.Duration
	}{
		"disabled rate": {
			transferred: 100,
		},
		"whole seconds": {
			transferred: 300,
			rate:        100,
			expect:      3 * time.Second,
		},
		"fractional seconds": {
			transferred: 150,
			rate:        100,
			expect:      1500 * time.Millisecond,
		},
		"large values saturate": {
			transferred: math.MaxUint64,
			rate:        1,
			expect:      time.Duration(math.MaxInt64),
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			// WHEN
			actual := bytesToDuration(tc.transferred, tc.rate)

			// THEN
			require.Equal(t, tc.expect, actual)
		})
	}
}
