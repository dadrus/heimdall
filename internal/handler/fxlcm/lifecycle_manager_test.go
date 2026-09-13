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
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/handler/fxlcm/mocks"
	"github.com/dadrus/heimdall/internal/handler/listener"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestLifecycleManagerStart(t *testing.T) {
	for uc, tc := range map[string]struct {
		setup      func(t *testing.T, srv *mocks.ServerMock) <-chan struct{}
		assert     func(t *testing.T, exit *testsupport.PatchedOSExit, logs string)
		waitFor    string
		expectExit bool
	}{
		"successful start": {
			setup: func(t *testing.T, srv *mocks.ServerMock) <-chan struct{} {
				t.Helper()

				served := make(chan struct{})
				srv.EXPECT().Serve(mock.Anything).RunAndReturn(func(net.Listener) error {
					close(served)

					return nil
				})

				return served
			},
			assert: func(t *testing.T, exit *testsupport.PatchedOSExit, logs string) {
				t.Helper()

				require.False(t, exit.Called())
				assert.Contains(t, logs, "Starting listening")
				assert.NotContains(t, logs, "error")
			},
			waitFor: "Starting listening",
		},
		"failed to start": {
			setup: func(t *testing.T, srv *mocks.ServerMock) <-chan struct{} {
				t.Helper()

				served := make(chan struct{})
				srv.EXPECT().Serve(mock.Anything).RunAndReturn(func(net.Listener) error {
					close(served)

					return assert.AnError
				})

				return served
			},
			assert: func(t *testing.T, exit *testsupport.PatchedOSExit, logs string) {
				t.Helper()

				require.True(t, exit.Called())
				assert.Contains(t, logs, "Starting listening")
				assert.Contains(t, logs, assert.AnError.Error())
			},
			waitFor:    assert.AnError.Error(),
			expectExit: true,
		},
		"started and resumed successfully": {
			setup: func(t *testing.T, srv *mocks.ServerMock) <-chan struct{} {
				t.Helper()

				served := make(chan struct{})
				srv.EXPECT().Serve(mock.Anything).RunAndReturn(func(net.Listener) error {
					close(served)

					return http.ErrServerClosed
				})

				return served
			},
			assert: func(t *testing.T, exit *testsupport.PatchedOSExit, logs string) {
				t.Helper()

				require.False(t, exit.Called())
				assert.Contains(t, logs, "Starting listening")
				assert.NotContains(t, logs, "error")
			},
			waitFor: "Service stopped",
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			exit, err := testsupport.PatchOSExit(t, func(int) {})
			require.NoError(t, err)

			port, err := testsupport.GetFreePort()
			require.NoError(t, err)

			srv := mocks.NewServerMock(t)
			served := tc.setup(t, srv)

			tb := &testsupport.TestingLog{TB: t}
			logger := zerolog.New(zerolog.TestWriter{T: tb})

			lf, err := listener.NewFactory(
				fmt.Sprintf("127.0.0.1:%d", port),
				nil,
				0,
				nil,
			)
			require.NoError(t, err)

			lcm := &LifecycleManager{
				ServiceName:     "foo",
				Server:          srv,
				ListenerFactory: lf,
				Logger:          logger,
			}

			// WHEN
			err = lcm.Start(t.Context())

			// THEN
			require.NoError(t, err)
			select {
			case <-served:
			case <-time.After(time.Second):
				require.FailNow(t, "server was not started")
			}

			require.Eventually(t, func() bool {
				if !strings.Contains(tb.CollectedLog(), tc.waitFor) {
					return false
				}

				return !tc.expectExit || exit.Called()
			}, time.Second, 10*time.Millisecond)
			tc.assert(t, exit, tb.CollectedLog())
		})
	}
}

func TestLifecycleManagerStop(t *testing.T) {
	t.Parallel()

	forceCloseErr := errors.New("force close failed")

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, srv *mocks.ServerMock)
		assert func(t *testing.T, err error, logs string)
	}{
		"stopped gracefully": {
			setup: func(t *testing.T, srv *mocks.ServerMock) {
				t.Helper()

				srv.EXPECT().Shutdown(mock.Anything).Return(nil)
			},
			assert: func(t *testing.T, err error, logs string) {
				t.Helper()

				require.NoError(t, err)
				assert.Contains(t, logs, "Tearing down service")
				assert.NotContains(t, logs, "Graceful shutdown failed")
			},
		},
		"graceful shutdown failed and service is forced to stop": {
			setup: func(t *testing.T, srv *mocks.ServerMock) {
				t.Helper()

				srv.EXPECT().Shutdown(mock.Anything).Return(assert.AnError)
				srv.EXPECT().Close().Return(nil)
			},
			assert: func(t *testing.T, err error, logs string) {
				t.Helper()

				require.ErrorIs(t, err, errServiceStop)
				require.ErrorIs(t, err, errGracefulShutdown)
				require.ErrorIs(t, err, assert.AnError)
				require.NotErrorIs(t, err, errForcedShutdown)
				require.ErrorContains(t, err, "foo service")
				assert.Contains(t, logs, "Graceful shutdown failed, forcing service to stop")
				assert.Contains(t, logs, assert.AnError.Error())
				assert.NotContains(t, logs, forceCloseErr.Error())
			},
		},
		"graceful and forced shutdown fail": {
			setup: func(t *testing.T, srv *mocks.ServerMock) {
				t.Helper()

				srv.EXPECT().Shutdown(mock.Anything).Return(assert.AnError)
				srv.EXPECT().Close().Return(forceCloseErr)
			},
			assert: func(t *testing.T, err error, logs string) {
				t.Helper()

				require.ErrorIs(t, err, errServiceStop)
				require.ErrorIs(t, err, errGracefulShutdown)
				require.ErrorIs(t, err, errForcedShutdown)
				require.ErrorIs(t, err, assert.AnError)
				require.ErrorIs(t, err, forceCloseErr)
				require.ErrorContains(t, err, "foo service")

				assert.Contains(t, logs, "Graceful shutdown failed, forcing service to stop")
				assert.Contains(t, logs, "Forced shutdown failed")
				assert.Contains(t, logs, forceCloseErr.Error())
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
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
			err := lcm.Stop(t.Context())

			// THEN
			tc.assert(t, err, tb.CollectedLog())
		})
	}
}

func TestGracefulShutdownContext(t *testing.T) {
	t.Parallel()

	parent, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	parentDeadline, ok := parent.Deadline()
	require.True(t, ok)

	graceCtx, graceCancel := gracefulShutdownContext(parent)
	defer graceCancel()

	graceDeadline, ok := graceCtx.Deadline()
	require.True(t, ok)
	assert.Equal(t, maxForceCloseTail, parentDeadline.Sub(graceDeadline))
}
