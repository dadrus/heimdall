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

package proxy

import (
	"net/http"
	"strings"

	"github.com/dadrus/heimdall/internal/handler/requestcontext"
)

type upgradeKind uint8

const (
	upgradeKindNone upgradeKind = iota
	upgradeKindOther
	upgradeKindWebSocket
)

func classifyUpgrade(req *http.Request) upgradeKind {
	if !isUpgradeRequest(req) {
		return upgradeKindNone
	}

	if headerValuesContainToken(req.Header.Values("Upgrade"), "websocket") {
		return upgradeKindWebSocket
	}

	return upgradeKindOther
}

func isUpgradeRequest(req *http.Request) bool {
	if len(req.Header.Get("Upgrade")) == 0 {
		return false
	}

	for option := range requestcontext.ConnectionOptions(req.Header) {
		if option == "Upgrade" {
			return true
		}
	}

	return false
}

func headerValuesContainToken(values []string, expected string) bool {
	for _, value := range values {
		for token := range strings.SplitSeq(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), expected) {
				return true
			}
		}
	}

	return false
}
