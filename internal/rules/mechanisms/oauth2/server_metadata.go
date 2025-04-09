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

package oauth2

import (
	"fmt"
	"strings"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/endpoint"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type ServerMetadata struct {
	Issuer                string
	JWKSEndpoint          *endpoint.Endpoint
	IntrospectionEndpoint *endpoint.Endpoint
}

func (sm ServerMetadata) verify(usedMetadataURL string) error {
	var (
		expectedIssuer string
		uriPrefix      string
		uriSuffix      string
	)

	parts := strings.Split(usedMetadataURL, ".well-known/")
	uriPrefix = parts[0]

	if len(parts) > 1 {
		// this is actually not compliant, but there are corresponding implementations out there in the wild
		uriSuffix = strings.TrimSuffix(parts[1], "/")
	}

	if strings.Contains(uriSuffix, "/") {
		expectedIssuer = fmt.Sprintf("%s%s", uriPrefix, strings.Split(uriSuffix, "/")[1])
	} else {
		expectedIssuer = strings.TrimSuffix(uriPrefix, "/")
	}

	if sm.Issuer != expectedIssuer && sm.Issuer != expectedIssuer+"/" {
		return errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"expected issuer '%s' does not match issuer '%s' from the received metadata",
			expectedIssuer, sm.Issuer)
	}

	return nil
}
