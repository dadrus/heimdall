// Copyright 2022-2025 Dimitrij Drus <dadrus@gmx.de>
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

package config

import (
	"fmt"
	"time"

	"github.com/inhies/go-bytesize"
)

type ManagementConfig struct {
	Host        string                `koanf:"host"`
	Port        int                   `koanf:"port"`
	Requests    ManagementRequests    `koanf:"requests"`
	Responses   IngressResponses      `koanf:"responses"`
	Connections ManagementConnections `koanf:"connections"`
	CORS        *CORS                 `koanf:"cors,omitempty"`
	TLS         *TLS                  `koanf:"tls,omitempty"  validate:"enforced=notnil"`
}

type ManagementRequests struct {
	MaxInFlight int64                 `koanf:"max_in_flight"       validate:"gte=0"`
	ReadTimeout time.Duration         `koanf:"read_timeout,string" validate:"gte=0"`
	Headers     IngressRequestHeaders `koanf:"headers"`
	Body        ManagementRequestBody `koanf:"body"`
}

type ManagementRequestBody struct {
	MaxSize bytesize.ByteSize `koanf:"max_size" validate:"max_bytes=7EB"`
}

type ManagementConnections struct {
	Max         int           `koanf:"max"                 validate:"gte=0"`
	IdleTimeout time.Duration `koanf:"idle_timeout,string" validate:"gte=0"`
}

func (c ManagementConfig) Address() string { return fmt.Sprintf("%s:%d", c.Host, c.Port) }
