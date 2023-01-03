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
	"net/http"
	"strings"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type QueryParameterExtractStrategy struct {
	Name string
}

func (es QueryParameterExtractStrategy) GetAuthData(s heimdall.Context) (AuthData, error) {
	if val := s.RequestQueryParameter(es.Name); len(val) != 0 {
		return &queryParameterAuthData{
			name:  es.Name,
			value: strings.TrimSpace(val),
		}, nil
	}

	return nil, errorchain.NewWithMessagef(heimdall.ErrArgument, "no '%s' query parameter present", es.Name)
}

type queryParameterAuthData struct {
	name  string
	value string
}

func (c *queryParameterAuthData) ApplyTo(req *http.Request) {
	query := req.URL.Query()
	query.Add(c.name, c.value)
	req.URL.RawQuery = query.Encode()
}

func (c *queryParameterAuthData) Value() string {
	return c.value
}
