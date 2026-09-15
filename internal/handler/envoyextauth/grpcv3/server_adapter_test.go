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

package grpcv3

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"
)

type blockingServiceServer interface {
	Block(ctx context.Context, pb *emptypb.Empty) (*emptypb.Empty, error)
}

type blockingService struct {
	started chan struct{}
}

func (s *blockingService) Block(ctx context.Context, _ *emptypb.Empty) (*emptypb.Empty, error) {
	close(s.started)
	<-ctx.Done()

	return nil, ctx.Err()
}

func TestAdapterShutdown(t *testing.T) {
	t.Run("stops gracefully when there is no active work", func(t *testing.T) {
		adapter := &adapter{s: grpc.NewServer()}

		require.NoError(t, adapter.Shutdown(t.Context()))
	})

	t.Run("forces stop when graceful shutdown times out", func(t *testing.T) {
		listener := bufconn.Listen(1024 * 1024)
		service := &blockingService{started: make(chan struct{})}
		srv := grpc.NewServer()
		srv.RegisterService(&blockingServiceDesc, service)
		adapter := &adapter{s: srv}

		go func() {
			_ = adapter.Serve(listener)
		}()

		conn, err := grpc.NewClient(
			"passthrough:///bufnet",
			grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
				return listener.Dial()
			}),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		require.NoError(t, err)
		t.Cleanup(func() {
			srv.Stop()
			_ = conn.Close()
			_ = listener.Close()
		})

		rpcDone := make(chan error, 1)
		go func() {
			rpcDone <- conn.Invoke(
				t.Context(),
				"/test.BlockingService/Block",
				&emptypb.Empty{},
				&emptypb.Empty{},
			)
		}()

		select {
		case <-service.started:
		case <-time.After(time.Second):
			require.FailNow(t, "gRPC request was not started")
		}

		graceCtx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
		defer cancel()

		err = adapter.Shutdown(graceCtx)
		require.ErrorIs(t, err, context.DeadlineExceeded)

		select {
		case err = <-rpcDone:
			require.Error(t, err)
		case <-time.After(time.Second):
			require.FailNow(t, "forced stop did not terminate the active RPC")
		}
	})
}

var blockingServiceDesc = grpc.ServiceDesc{ //nolint:gochecknoglobals
	ServiceName: "test.BlockingService",
	HandlerType: (*blockingServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Block",
			Handler: func(
				srv any,
				ctx context.Context,
				dec func(any) error,
				interceptor grpc.UnaryServerInterceptor,
			) (any, error) {
				request := new(emptypb.Empty)
				if err := dec(request); err != nil {
					return nil, err
				}

				if interceptor == nil {
					return srv.(blockingServiceServer).Block(ctx, request)
				}

				info := &grpc.UnaryServerInfo{
					Server:     srv,
					FullMethod: "/test.BlockingService/Block",
				}
				handler := func(ctx context.Context, request any) (any, error) {
					return srv.(blockingServiceServer).Block(ctx, request.(*emptypb.Empty))
				}

				return interceptor(ctx, request, info, handler)
			},
		},
	},
}
