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
	Host           string             `koanf:"host"`
	Port           int                `koanf:"port"`
	Timeout        Timeout            `koanf:"timeout"`
	Requests       IngressRequests    `koanf:"requests"`
	Responses      IngressResponses   `koanf:"responses"`
	Connections    IngressConnections `koanf:"connections"`
	Upstream       UpstreamConfig     `koanf:"upstream"`
	CORS           *CORS              `koanf:"cors,omitempty"`
	TLS            *TLS               `koanf:"tls,omitempty"             validate:"enforced=notnil"`
	TrustedProxies []string           `koanf:"trusted_proxies,omitempty" validate:"enforced=secure_networks"`
	Respond        RespondConfig      `koanf:"respond"`
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

type IngressRequests struct {
	MaxInFlight int64                 `koanf:"max_in_flight"       validate:"gte=0"`
	ReadTimeout time.Duration         `koanf:"read_timeout,string" validate:"gte=0"`
	Headers     IngressRequestHeaders `koanf:"headers"`
	Body        IngressRequestBody    `koanf:"body"`
}

type IngressRequestHeaders struct {
	MaxSize     bytesize.ByteSize `koanf:"max_size"            validate:"gt=0,max_bytes=2047MB"`
	ReadTimeout time.Duration     `koanf:"read_timeout,string" validate:"gte=0"`
}

type IngressRequestBody struct {
	MaxSize         bytesize.ByteSize `koanf:"max_size"                 validate:"max_bytes=7EB"`
	ReadIdleTimeout time.Duration     `koanf:"read_idle_timeout,string" validate:"gte=0,required_with=ReadMinRate"`
	ReadMinRate     int64             `koanf:"read_min_rate"            validate:"gte=0"`
}

type IngressResponses struct {
	WriteTimeout     time.Duration `koanf:"write_timeout,string"      validate:"gte=0"`
	WriteIdleTimeout time.Duration `koanf:"write_idle_timeout,string" validate:"gte=0,required_with=WriteMinRate"`
	WriteMinRate     int64         `koanf:"write_min_rate"            validate:"gte=0"`
}

type IngressConnections struct {
	Max              int                `koanf:"max"                       validate:"gte=0"`
	IdleTimeout      time.Duration      `koanf:"idle_timeout,string"       validate:"gte=0"`
	WriteIdleTimeout time.Duration      `koanf:"write_idle_timeout,string" validate:"gte=0"`
	Streams          MultiplexedStreams `koanf:"streams"`
	Liveness         ConnectionLiveness `koanf:"liveness"`
}

type MultiplexedStreams struct {
	MaxConcurrent int `koanf:"max_concurrent" validate:"gt=0,lte=4294967295"`
}

type ConnectionLiveness struct {
	ProbeAfter   time.Duration `koanf:"probe_after,string"   validate:"gte=0"`
	ProbeTimeout time.Duration `koanf:"probe_timeout,string" validate:"gt=0"`
}

type UpstreamConfig struct {
	Connections UpstreamConnections `koanf:"connections"`
	Requests    UpstreamRequests    `koanf:"requests"`
	Responses   UpstreamResponses   `koanf:"responses"`
}

type UpstreamConnections struct {
	MaxPerHost     int `koanf:"max_per_host"      validate:"gte=0"`
	MaxIdle        int `koanf:"max_idle"          validate:"gt=0"`
	MaxIdlePerHost int `koanf:"max_idle_per_host" validate:"gt=0,ltefield=MaxIdle"`

	DialTimeout         time.Duration      `koanf:"dial_timeout,string"          validate:"gte=0"`
	TLSHandshakeTimeout time.Duration      `koanf:"tls_handshake_timeout,string" validate:"gte=0"`
	IdleTimeout         time.Duration      `koanf:"idle_timeout,string"          validate:"gte=0"`
	WriteIdleTimeout    time.Duration      `koanf:"write_idle_timeout,string"    validate:"gte=0"`
	Liveness            ConnectionLiveness `koanf:"liveness"`
}

type UpstreamRequests struct {
	ExpectContinueTimeout time.Duration `koanf:"expect_continue_timeout,string" validate:"gte=0"`
	WriteIdleTimeout      time.Duration `koanf:"write_idle_timeout,string"      validate:"gte=0"`
}

type UpstreamResponses struct {
	Headers UpstreamResponseHeaders `koanf:"headers"`
	Body    UpstreamResponseBody    `koanf:"body"`
}

type UpstreamResponseHeaders struct {
	MaxSize     bytesize.ByteSize `koanf:"max_size"            validate:"gt=0,max_bytes=7EB"`
	ReadTimeout time.Duration     `koanf:"read_timeout,string" validate:"gte=0"`
}

type UpstreamResponseBody struct {
	ReadIdleTimeout time.Duration `koanf:"read_idle_timeout,string" validate:"gte=0"`
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
		RequestBodyTooLarge ResponseOverride `koanf:"request_body_too_large"`
		TooManyRequests     ResponseOverride `koanf:"too_many_requests"`
		NoRuleError         ResponseOverride `koanf:"no_rule_error"`
	} `koanf:"with"`
}
