// Copyright 2023 Dimitrij Drus <dadrus@gmx.de>
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

package fxlcm

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/handler/fxlcm/mocks"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestLifecycleManagerStart(t *testing.T) {
	for _, tc := range []struct {
		uc     string
		setup  func(t *testing.T, srv *mocks.ServerMock)
		assert func(t *testing.T, exit *testsupport.PatchedOSExit, logs string)
	}{
		{
			uc: "successful start",
			setup: func(t *testing.T, srv *mocks.ServerMock) {
				t.Helper()

				srv.EXPECT().Serve(mock.Anything).Return(nil)
			},
			assert: func(t *testing.T, exit *testsupport.PatchedOSExit, logs string) {
				t.Helper()

				require.False(t, exit.Called)
				assert.Contains(t, logs, "Starting listening")
				assert.NotContains(t, logs, "error")
			},
		},
		{
			uc: "failed to start",
			setup: func(t *testing.T, srv *mocks.ServerMock) {
				t.Helper()

				srv.EXPECT().Serve(mock.Anything).Return(errors.New("test error"))
			},
			assert: func(t *testing.T, exit *testsupport.PatchedOSExit, logs string) {
				t.Helper()

				require.True(t, exit.Called)
				assert.Contains(t, logs, "Starting listening")
				assert.Contains(t, logs, "test error")
			},
		},
		{
			uc: "started and resumed successfully",
			setup: func(t *testing.T, srv *mocks.ServerMock) {
				t.Helper()

				srv.EXPECT().Serve(mock.Anything).Return(http.ErrServerClosed)
			},
			assert: func(t *testing.T, exit *testsupport.PatchedOSExit, logs string) {
				t.Helper()

				require.False(t, exit.Called)
				assert.Contains(t, logs, "Starting listening")
				assert.NotContains(t, logs, "error")
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			exit, err := testsupport.PatchOSExit(t, func(int) {})
			require.NoError(t, err)

			port, err := testsupport.GetFreePort()
			require.NoError(t, err)

			srv := mocks.NewServerMock(t)
			tc.setup(t, srv)

			tb := &testsupport.TestingLog{TB: t}
			logger := zerolog.New(zerolog.TestWriter{T: tb})

			lcm := &LifecycleManager{
				ServiceName:    "foo",
				ServiceAddress: fmt.Sprintf("127.0.0.1:%d", port),
				Server:         srv,
				Logger:         logger,
			}

			// WHEN
			err = lcm.Start(context.TODO())
			time.Sleep(50 * time.Millisecond)

			// THEN
			require.NoError(t, err)
			tc.assert(t, exit, tb.CollectedLog())
		})
	}
}

func TestLifecycleManagerStop(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		setup  func(t *testing.T, srv *mocks.ServerMock)
		assert func(t *testing.T, err error, logs string)
	}{
		{
			uc: "stopped without error",
			setup: func(t *testing.T, srv *mocks.ServerMock) {
				t.Helper()

				srv.EXPECT().Shutdown(mock.Anything).Return(nil)
			},
			assert: func(t *testing.T, err error, logs string) {
				t.Helper()

				require.NoError(t, err)
				assert.Contains(t, logs, "Tearing down service")
				assert.NotContains(t, logs, "error")
			},
		},
		{
			uc: "stopped with error",
			setup: func(t *testing.T, srv *mocks.ServerMock) {
				t.Helper()

				srv.EXPECT().Shutdown(mock.Anything).Return(errors.New("test error"))
			},
			assert: func(t *testing.T, err error, logs string) {
				t.Helper()

				require.Error(t, err)
				assert.Contains(t, logs, "Tearing down service")
				assert.Contains(t, logs, "test error")
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			srv := mocks.NewServerMock(t)
			tc.setup(t, srv)

			tb := &testsupport.TestingLog{TB: t}
			logger := zerolog.New(zerolog.TestWriter{T: tb})

			lcm := &LifecycleManager{
				ServiceName: "foo",
				Server:      srv,
				Logger:      logger,
			}

			// WHEN
			err := lcm.Stop(context.TODO())

			// THEN
			tc.assert(t, err, tb.CollectedLog())
		})
	}
}
