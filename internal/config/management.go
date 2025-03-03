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

import "fmt"

type ManagementConfig struct {
	Host        string      `koanf:"host"`
	Port        int         `koanf:"port"`
	Timeout     Timeout     `koanf:"timeout"`
	BufferLimit BufferLimit `koanf:"buffer_limit"`
	CORS        *CORS       `koanf:"cors,omitempty"`
	TLS         *TLS        `koanf:"tls,omitempty"  validate:"enforced=notnil"`
}

func (c ManagementConfig) Address() string { return fmt.Sprintf("%s:%d", c.Host, c.Port) }
