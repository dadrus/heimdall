package fxlcm

import (
	"context"
	"errors"
	"net/http"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/handler/listener"
)

type LifecycleManager struct {
	Service string
	Server  *http.Server
	Logger  zerolog.Logger
	TLSConf *config.TLS
}

func (m *LifecycleManager) Start(_ context.Context) error {
	ln, err := listener.New("tcp", m.Server.Addr, m.TLSConf)
	if err != nil {
		m.Logger.Fatal().Err(err).Str("_service", m.Service).Msg("Could not create listener")

		return err
	}

	go func() {
		m.Logger.Info().
			Str("_address", ln.Addr().String()).
			Str("_service", m.Service).
			Msg("Starting listening")

		if err = m.Server.Serve(ln); err != nil {
			if !errors.Is(err, http.ErrServerClosed) {
				m.Logger.Fatal().Err(err).Str("_service", m.Service).Msg("Could not start service")
			}
		}
	}()

	return nil
}

func (m *LifecycleManager) Stop(ctx context.Context) error {
	m.Logger.Info().Str("_service", m.Service).Msg("Tearing down service")

	return m.Server.Shutdown(ctx)
}
