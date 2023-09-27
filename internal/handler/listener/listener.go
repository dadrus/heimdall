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
	"crypto/tls"
	"net"
	"sync/atomic"
	"time"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/keystore"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type conn struct {
	net.Conn

	writeTimeout  atomic.Int64
	resetDeadline atomic.Bool
	bytesWritten  atomic.Int32
}

func (c *conn) Write(data []byte) (int, error) {
	if c.resetDeadline.Load() && c.bytesWritten.Load() > 0 {
		c.bytesWritten.Store(0)

		if err := c.Conn.SetWriteDeadline(time.Now().Add(time.Duration(c.writeTimeout.Load()))); err != nil {
			return 0, err
		}
	}

	n, err := c.Conn.Write(data)
	if c.resetDeadline.Load() {
		c.bytesWritten.Add(int32(n))
	}

	return n, err
}

func (c *conn) SetDeadline(deadline time.Time) error {
	if deadline.Equal(time.Time{}) {
		c.resetDeadline.Store(false)
	} else {
		c.writeTimeout.Store(int64(time.Until(deadline)))
	}

	return c.Conn.SetDeadline(deadline)
}

func (c *conn) SetWriteDeadline(deadline time.Time) error {
	if deadline.Equal(time.Time{}) {
		c.resetDeadline.Store(false)
	} else {
		c.writeTimeout.Store(int64(time.Until(deadline)))
	}

	return c.Conn.SetWriteDeadline(deadline)
}

func (c *conn) MonitorAndResetDeadlines(flag bool) {
	c.resetDeadline.Store(flag)
}

type listener struct {
	net.Listener
}

func (l *listener) Accept() (net.Conn, error) {
	con, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return &conn{Conn: con}, nil
}

func New(network, address string, tlsConf *config.TLS) (net.Listener, error) {
	listnr, err := net.Listen(network, address)
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal, "failed creating listener").
			CausedBy(err)
	}

	wrapped := &listener{Listener: listnr}

	if tlsConf != nil {
		return newTLSListener(tlsConf, wrapped)
	}

	return wrapped, nil
}

func newTLSListener(tlsConf *config.TLS, listener net.Listener) (net.Listener, error) {
	var (
		entry *keystore.Entry
		err   error
	)

	ks, err := keystore.NewKeyStoreFromPEMFile(tlsConf.KeyStore.Path, tlsConf.KeyStore.Password)
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal, "failed loading keystore").
			CausedBy(err)
	}

	if len(tlsConf.KeyID) != 0 {
		if entry, err = ks.GetKey(tlsConf.KeyID); err != nil {
			return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
				"failed retrieving key from key store").CausedBy(err)
		}
	} else {
		entry = ks.Entries()[0]
	}

	cert, err := keystore.ToTLSCertificate(entry)
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"key store entry is not suitable for TLS").CausedBy(err)
	}

	// nolint:gosec
	// configuration ensures, TLS versions below 1.2 are not possible
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tlsConf.MinVersion.OrDefault(),
		NextProtos:   []string{"h2", "http/1.1"},
	}

	if cfg.MinVersion != tls.VersionTLS13 {
		cfg.CipherSuites = tlsConf.CipherSuites.OrDefault()
	}

	return tls.NewListener(listener, cfg), nil
}
