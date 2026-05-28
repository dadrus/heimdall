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

package listener

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/secrets"
	"github.com/dadrus/heimdall/internal/x/tlsx"
)

type listener struct {
	net.Listener
}

type Listener interface {
	net.Listener

	TLSEnabled() bool
}

type listenerWrapper struct {
	net.Listener

	tlsEnabled bool
}

func (l *listenerWrapper) TLSEnabled() bool { return l.tlsEnabled }

//nolint:gochecknoglobals // package-local seam for listener unit tests
var listen = func(ctx context.Context, address string) (net.Listener, error) {
	var lc net.ListenConfig

	return lc.Listen(ctx, "tcp", address)
}

func (l *listener) Accept() (net.Conn, error) {
	con, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return &conn{Conn: con}, nil
}

type Factory struct {
	address    string
	tlsConfig  *tls.Config
	tlsEnabled bool
}

func NewFactory(
	address string,
	tlsConf *config.TLS,
	secretResolver secrets.Resolver,
) (Factory, error) {
	var tlsConfig *tls.Config

	if tlsConf != nil {
		cfg, err := tlsx.ToServerTLSConfig(
			context.Background(),
			secretResolver,
			tlsConf,
			// key observer, falls noch Teil der Signatur
		)
		if err != nil {
			return Factory{}, err
		}

		tlsConfig = cfg
	}

	return Factory{
		address:    address,
		tlsConfig:  tlsConfig,
		tlsEnabled: tlsConf != nil,
	}, nil
}

func (f Factory) Create(ctx context.Context) (net.Listener, error) {
	listnr, err := listen(ctx, f.address)
	if err != nil {
		return nil, err
	}

	listnr = &listener{Listener: listnr}

	if f.tlsConfig != nil {
		listnr = tls.NewListener(listnr, f.tlsConfig)
	}

	return &listenerWrapper{
		Listener:   listnr,
		tlsEnabled: f.tlsEnabled,
	}, nil
}
