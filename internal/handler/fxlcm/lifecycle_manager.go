package fxlcm

import (
	"context"
	"errors"
	"net"
	"net/http"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/handler/listener"
)

//go:generate mockery --name Server --structname ServerMock

type Server interface {
	Serve(l net.Listener) error
	Shutdown(ctx context.Context) error
}

type LifecycleManager struct {
	ServiceName    string
	ServiceAddress string
	Server         Server
	Logger         zerolog.Logger
	TLSConf        *config.TLS
}

func (m *LifecycleManager) Start(_ context.Context) error {
	ln, err := listener.New("tcp", m.ServiceAddress, m.TLSConf)
	if err != nil {
		m.Logger.Fatal().Err(err).Str("_service", m.ServiceName).Msg("Could not create listener")

		return err
	}

	go func() {
		m.Logger.Info().
			Str("_address", ln.Addr().String()).
			Str("_service", m.ServiceName).
			Msg("Starting listening")

		if err = m.Server.Serve(ln); err != nil {
			if !errors.Is(err, http.ErrServerClosed) {
				m.Logger.Fatal().Err(err).Str("_service", m.ServiceName).Msg("Could not start service")
			} else {
				m.Logger.Info().Str("_service", m.ServiceName).Msg("Service stopped")
			}
		}
	}()

	return nil
}

func (m *LifecycleManager) Stop(ctx context.Context) error {
	m.Logger.Info().Str("_service", m.ServiceName).Msg("Tearing down service")

	err := m.Server.Shutdown(ctx)
	if err != nil {
		m.Logger.Warn().Err(err).Str("_service", m.ServiceName).Msg("Graceful shutdown failed")
	}

	return err
}
