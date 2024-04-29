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

package authenticators

import (
	"github.com/tidwall/gjson"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/subject"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type PrincipalInfo struct {
	IDFrom         string `mapstructure:"id"         validate:"required"`
	AttributesFrom string `mapstructure:"attributes"`
}

func (s *PrincipalInfo) CreatePrincipal(rawData []byte) (*subject.Principal, error) {
	attributesFrom := "@this"
	if len(s.AttributesFrom) != 0 {
		attributesFrom = s.AttributesFrom
	}

	subjectID := gjson.GetBytes(rawData, s.IDFrom).String()
	if len(subjectID) == 0 {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"could not extract subject identifier using '%s' template", s.IDFrom)
	}

	attributes := gjson.GetBytes(rawData, attributesFrom).Value()
	if attributes == nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"could not extract attributes using '%s' template", attributesFrom)
	}

	attrs, ok := attributes.(map[string]any)
	if !ok {
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal, "unexpected response from gjson template")
	}

	return &subject.Principal{
		ID:         subjectID,
		Attributes: attrs,
	}, nil
}
