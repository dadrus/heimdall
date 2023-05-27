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

package extractors

import (
	"fmt"
	"strings"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type HeaderValueExtractStrategy struct {
	Name   string
	Schema string
}

func (es HeaderValueExtractStrategy) GetAuthData(s heimdall.Context) (string, error) {
	if val := s.Request().Header(es.Name); len(val) != 0 {
		if len(es.Schema) != 0 && !strings.HasPrefix(val, fmt.Sprintf("%s ", es.Schema)) {
			return "", errorchain.NewWithMessagef(heimdall.ErrArgument,
				"'%s' header present, but without required '%s' schema", es.Name, es.Schema)
		}

		return strings.TrimSpace(strings.TrimPrefix(val, es.Schema)), nil
	}

	return "", errorchain.NewWithMessagef(heimdall.ErrArgument, "no '%s' header present", es.Name)
}
