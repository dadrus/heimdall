// Copyright 2022 Dimitrij Drus <dadrus@gmx.de>
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

type ServeConfig struct {
	Host             string           `koanf:"host"`
	Port             int              `koanf:"port"`
	Timeout          Timeout          `koanf:"timeout"`
	BufferLimit      BufferLimit      `koanf:"buffer_limit"`
	ConnectionsLimit ConnectionsLimit `koanf:"connections_limit"`
	CORS             *CORS            `koanf:"cors,omitempty"`
	TLS              *TLS             `koanf:"tls,omitempty"`
	TrustedProxies   *[]string        `koanf:"trusted_proxies,omitempty"`
	Respond          RespondConfig    `koanf:"respond"`
}

func (c ServeConfig) Address() string { return fmt.Sprintf("%s:%d", c.Host, c.Port) }

type BufferLimit struct {
	Read  bytesize.ByteSize `koanf:"read"  mapstructure:"read"`
	Write bytesize.ByteSize `koanf:"write" mapstructure:"write"`
}

type Timeout struct {
	Read  time.Duration `koanf:"read,string"  mapstructure:"read"`
	Write time.Duration `koanf:"write,string" mapstructure:"write"`
	Idle  time.Duration `koanf:"idle,string"  mapstructure:"idle"`
}

type ConnectionsLimit struct {
	MaxPerHost     int `koanf:"max_per_host"`
	MaxIdle        int `koanf:"max_idle"`
	MaxIdlePerHost int `koanf:"max_idle_per_host"`
}

type CORS struct {
	AllowedOrigins   []string      `koanf:"allowed_origins"`
	AllowedMethods   []string      `koanf:"allowed_methods"`
	AllowedHeaders   []string      `koanf:"allowed_headers"`
	ExposedHeaders   []string      `koanf:"exposed_headers"`
	AllowCredentials bool          `koanf:"allow_credentials"`
	MaxAge           time.Duration `koanf:"max_age,string"`
}

type ResponseOverride struct {
	Code int `koanf:"code"`
}

type RespondConfig struct {
	Verbose bool `koanf:"verbose"`
	With    struct {
		Accepted            ResponseOverride `koanf:"accepted"`
		ArgumentError       ResponseOverride `koanf:"argument_error"`
		AuthenticationError ResponseOverride `koanf:"authentication_error"`
		AuthorizationError  ResponseOverride `koanf:"authorization_error"`
		CommunicationError  ResponseOverride `koanf:"communication_error"`
		InternalError       ResponseOverride `koanf:"internal_error"`
		NoRuleError         ResponseOverride `koanf:"no_rule_error"`
	} `koanf:"with"`
}
