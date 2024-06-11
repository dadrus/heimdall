// Copyright 2024 Dimitrij Drus <dadrus@gmx.de>
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

package tlsx

import (
	"github.com/dadrus/heimdall/internal/otel/metrics/certificate"
	"github.com/dadrus/heimdall/internal/watcher"
)

type noopObserver struct{}

func (*noopObserver) Add(_ certificate.Supplier) {}
func (*noopObserver) Start() error               { return nil }

type options struct {
	name                string
	serverAuthRequired  bool
	clientAuthRequired  bool
	secretsWatcher      watcher.Watcher
	certificateObserver certificate.Observer
}

func newOptions() *options {
	return &options{
		name:                "unknown",
		secretsWatcher:      &watcher.NoopWatcher{},
		certificateObserver: &noopObserver{},
	}
}

type Option func(*options)

func WithServerAuthentication(flag bool) Option {
	return func(o *options) {
		o.serverAuthRequired = flag
	}
}

func WithClientAuthentication(flag bool) Option {
	return func(o *options) {
		o.clientAuthRequired = flag
	}
}

func WithSecretsWatcher(cw watcher.Watcher) Option {
	return func(o *options) {
		o.secretsWatcher = cw
	}
}

func WithCertificateObserver(name string, co certificate.Observer) Option {
	return func(o *options) {
		o.name = name
		o.certificateObserver = co
	}
}
