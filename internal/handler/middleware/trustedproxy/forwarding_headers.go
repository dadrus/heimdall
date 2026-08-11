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

package trustedproxy

import "strings"

var forwardingHeaders = [...]string{ //nolint:gochecknoglobals
	"Forwarded",
	"X-Forwarded-For",
	"X-Forwarded-Proto",
	"X-Forwarded-Host",
	"X-Forwarded-Uri",
	"X-Forwarded-Path",
	"X-Forwarded-Method",
}

func RemoveForwardingHeaders(remove func(string)) {
	for _, name := range forwardingHeaders {
		remove(name)
	}
}

func IsForwardingHeader(name string) bool {
	switch {
	case strings.EqualFold(name, "Forwarded"):
		return true
	case strings.EqualFold(name, "X-Forwarded-For"):
		return true
	case strings.EqualFold(name, "X-Forwarded-Proto"):
		return true
	case strings.EqualFold(name, "X-Forwarded-Host"):
		return true
	case strings.EqualFold(name, "X-Forwarded-Uri"):
		return true
	case strings.EqualFold(name, "X-Forwarded-Path"):
		return true
	case strings.EqualFold(name, "X-Forwarded-Method"):
		return true
	default:
		return false
	}
}
