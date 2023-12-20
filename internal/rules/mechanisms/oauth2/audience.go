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

package oauth2

import (
	"strings"

	"github.com/goccy/go-json"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// Audience represents the recipients that the token is intended for.
type Audience []string

// UnmarshalJSON reads an audience from its JSON representation.
func (s *Audience) UnmarshalJSON(b []byte) error {
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return errorchain.NewWithMessage(heimdall.ErrConfiguration, "failed to unmarshal audience").CausedBy(err)
	}

	switch value := v.(type) {
	case string:
		*s = strings.Split(value, " ")
	case []interface{}:
		array := make([]string, len(value))

		for idx, val := range value {
			s, ok := val.(string)
			if !ok {
				return errorchain.NewWithMessage(heimdall.ErrConfiguration, "failed to parse audience array")
			}

			array[idx] = s
		}

		*s = array
	default:
		return errorchain.NewWithMessage(heimdall.ErrConfiguration, "unexpected content for audience")
	}

	return nil
}
