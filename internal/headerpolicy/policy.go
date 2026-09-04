// Copyright 2026 Dimitrij Drus <dadrus@gmx.de>
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

package headerpolicy

import (
	"net/http"
	"strings"
)

type Class uint8

const (
	Ordinary Class = iota
	ProxyOwned
	Transport
)

type metadata struct {
	class         Class
	sanitizeInput bool
}

func Classify(name string) Class {
	return metadataFor(name).class
}

func ShouldSanitizeInput(name string) bool {
	return metadataFor(name).sanitizeInput
}

func metadataFor(name string) metadata {
	if strings.HasPrefix(name, ":") {
		return metadata{class: Transport}
	}

	name = http.CanonicalHeaderKey(name)

	switch name {
	case "Forwarded",
		"X-Forwarded-For",
		"X-Forwarded-Host",
		"X-Forwarded-Proto":
		return metadata{class: ProxyOwned}
	case "X-Forwarded-Method",
		"X-Forwarded-Uri",
		"X-Forwarded-Path":
		return metadata{
			class:         ProxyOwned,
			sanitizeInput: true,
		}
	}

	if strings.HasPrefix(name, "X-Forwarded-") {
		return metadata{class: ProxyOwned}
	}

	if strings.HasPrefix(name, "X-Envoy-") {
		return metadata{class: ProxyOwned}
	}

	switch name {
	case "Connection",
		"Proxy-Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade":
		return metadata{
			class:         Transport,
			sanitizeInput: true,
		}
	case "Content-Length":
		return metadata{class: Transport}
	default:
		return metadata{class: Ordinary}
	}
}
