package grpcv3

import (
	"context"
	"net"

	"google.golang.org/grpc"
)

type adapter struct {
	s *grpc.Server
}

func (a *adapter) Serve(l net.Listener) error { return a.s.Serve(l) }

func (a *adapter) Shutdown(ctx context.Context) error {
	done := make(chan struct{})

	go func() {
		a.s.GracefulStop()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
		a.s.Stop()
	}

	return nil
}
