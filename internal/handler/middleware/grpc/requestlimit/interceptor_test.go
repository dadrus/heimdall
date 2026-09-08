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

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/pipeline"
)

func TestNew(t *testing.T) {
	t.Parallel()

	t.Run("disabled limit allows concurrent requests", func(t *testing.T) {
		// GIVEN
		interceptor := New(0)

		requestEntered := make(chan struct{}, 2)
		releaseRequest := make(chan struct{})

		var releaseOnce sync.Once
		releaseRequests := func() {
			releaseOnce.Do(func() {
				close(releaseRequest)
			})
		}
		t.Cleanup(releaseRequests)

		handler := func(_ context.Context, req any) (any, error) {
			requestEntered <- struct{}{}

			<-releaseRequest

			return req, nil
		}

		requestDone := make(chan error, 2)

		// WHEN
		for range 2 {
			go func() {
				_, err := interceptor(t.Context(), struct{}{}, nil, handler)

				requestDone <- err
			}()
		}

		// THEN
		for range 2 {
			select {
			case <-requestEntered:
			case <-time.After(time.Second):
				require.FailNow(t, "request did not enter handler")
			}
		}

		releaseRequests()

		for range 2 {
			assert.NoError(t, <-requestDone)
		}
	})

	t.Run("rejects request while capacity is exhausted and releases capacity afterwards", func(t *testing.T) {
		// GIVEN
		interceptor := New(1)

		requestEntered := make(chan struct{}, 2)
		releaseRequest := make(chan struct{})

		var releaseOnce sync.Once
		releaseRequests := func() {
			releaseOnce.Do(func() {
				close(releaseRequest)
			})
		}
		t.Cleanup(releaseRequests)

		handler := func(_ context.Context, req any) (any, error) {
			requestEntered <- struct{}{}

			<-releaseRequest

			return req, nil
		}

		firstDone := make(chan error, 1)

		go func() {
			_, err := interceptor(t.Context(), struct{}{}, nil, handler)

			firstDone <- err
		}()

		select {
		case <-requestEntered:
		case <-time.After(time.Second):
			require.FailNow(t, "first request did not enter handler")
		}

		secondDone := make(chan error, 1)

		// WHEN
		go func() {
			_, err := interceptor(t.Context(), struct{}{}, nil, handler)

			secondDone <- err
		}()

		// THEN
		select {
		case err := <-secondDone:
			require.ErrorIs(t, err, pipeline.ErrTooManyRequests)
		case <-requestEntered:
			require.FailNow(t, "second request entered handler while capacity was exhausted")
		case <-time.After(time.Second):
			require.FailNow(t, "second request was not rejected immediately")
		}

		// WHEN
		releaseRequests()

		// THEN
		select {
		case err := <-firstDone:
			require.NoError(t, err)
		case <-time.After(time.Second):
			require.FailNow(t, "first request did not complete")
		}

		_, err := interceptor(t.Context(), struct{}{}, nil, handler)

		assert.NoError(t, err)
	})
}
