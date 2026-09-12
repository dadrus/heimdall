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
	"math/bits"
	"time"
)

type deadlineTracker struct {
	startedAt      time.Time
	hardDeadlineAt time.Time
	idleTimeout    time.Duration
	minRate        int64

	transferredBytes uint64
}

func newDeadlineTracker(hardTimeout, idleTimeout time.Duration, minRate int64, startedAt time.Time) deadlineTracker {
	tracker := deadlineTracker{
		startedAt:   startedAt,
		idleTimeout: idleTimeout,
		minRate:     minRate,
	}

	if hardTimeout > 0 {
		tracker.hardDeadlineAt = startedAt.Add(hardTimeout)
	}

	return tracker
}

// nextDeadline returns the next progress deadline using the following model:
// without a minimum rate every operation gets a fresh sliding idle window;
// with a minimum rate the allowance grows from a fixed start by one second
// per MinRate transferred bytes. A hard deadline caps either mode.
func (t *deadlineTracker) nextDeadline(now time.Time) time.Time {
	var deadline time.Time

	switch {
	case t.minRate > 0:
		allowance := addDurationSaturated(
			t.idleTimeout,
			bytesToDuration(t.transferredBytes, t.minRate),
		)
		deadline = t.startedAt.Add(allowance)
	case t.idleTimeout > 0:
		deadline = now.Add(t.idleTimeout)
	}

	if !t.hardDeadlineAt.IsZero() && (deadline.IsZero() || deadline.After(t.hardDeadlineAt)) {
		deadline = t.hardDeadlineAt
	}

	return deadline
}

func (t *deadlineTracker) hardDeadline() time.Time {
	return t.hardDeadlineAt
}

func (t *deadlineTracker) recordTransfer(transferred int) {
	if transferred <= 0 {
		return
	}

	bytes := uint64(transferred)
	if math.MaxUint64-t.transferredBytes < bytes {
		t.transferredBytes = math.MaxUint64

		return
	}

	t.transferredBytes += bytes
}

func addDurationSaturated(left, right time.Duration) time.Duration {
	maxDuration := time.Duration(math.MaxInt64)
	if right > 0 && maxDuration-left < right {
		return maxDuration
	}

	return left + right
}

func bytesToDuration(transferred uint64, rate int64) time.Duration {
	if transferred == 0 || rate <= 0 {
		return 0
	}

	ratePerSecond := uint64(rate)
	seconds := transferred / ratePerSecond
	maxSeconds := uint64(math.MaxInt64 / int64(time.Second))
	if seconds > maxSeconds {
		return time.Duration(math.MaxInt64)
	}

	result := time.Duration(seconds) * time.Second
	remainder := transferred % ratePerSecond
	if remainder == 0 {
		return result
	}

	high, low := bits.Mul64(remainder, uint64(time.Second))
	nanoseconds, _ := bits.Div64(high, low, ratePerSecond)
	// remainder is strictly smaller than ratePerSecond, therefore, the division
	// yields less than time.Second and cannot overflow time.Duration.
	fraction := time.Duration(nanoseconds) //nolint:gosec

	return addDurationSaturated(result, fraction)
}
