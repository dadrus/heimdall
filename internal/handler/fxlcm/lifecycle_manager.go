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
	"net"
	"net/http"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/handler/listener"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/otel/metrics/certificate"
	"github.com/dadrus/heimdall/internal/watcher"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

//go:generate mockery --name Server --structname ServerMock

type Server interface {
	Serve(l net.Listener) error
	Shutdown(ctx context.Context) error
}

type LifecycleManager struct {
	ServiceName         string
	ServiceAddress      string
	Server              Server
	Logger              zerolog.Logger
	TLSConf             *config.TLS
	FileWatcher         watcher.Watcher
	CertificateObserver certificate.Observer
}

func (m *LifecycleManager) Start(_ context.Context) error {
	ln, err := listener.New("tcp", m.ServiceName, m.ServiceAddress, m.TLSConf, m.FileWatcher, m.CertificateObserver)
	if err != nil {
		return errorchain.NewWithMessagef(heimdall.ErrInternal,
			"Could not create listener for %s service", m.ServiceName).
			CausedBy(err)
	}

	go func() {
		m.Logger.Info().
			Str("_address", ln.Addr().String()).
			Str("_service", m.ServiceName).
			Msg("Starting listening")

		if m.TLSConf == nil {
			m.Logger.Warn().
				Str("_service", m.ServiceName).
				Msg("TLS is disabled.")
		}

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
