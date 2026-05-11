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
	"github.com/dadrus/heimdall/internal/keyregistry"
	"github.com/dadrus/heimdall/internal/secrets"
	"github.com/dadrus/heimdall/internal/x/tlsx"
)

type listener struct {
	net.Listener
}

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

func New(
	ctx context.Context,
	address string,
	tlsConf *config.TLS,
	sm secrets.Manager,
	ko keyregistry.KeyObserver,
) (net.Listener, error) {
	listnr, err := listen(ctx, address)
	if err != nil {
		return nil, err
	}

	listnr = &listener{Listener: listnr}

	if tlsConf != nil {
		cfg, err := tlsx.ToServerTLSConfig(ctx, sm, tlsConf, ko)
		if err != nil {
			return nil, err
		}

		return tls.NewListener(listnr, cfg), nil
	}

	return listnr, nil
}
