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

package contenttype

import (
	"net/url"

	"github.com/dadrus/heimdall/internal/x/stringx"
)

type WWWFormUrlencodedDecoder struct{}

func (WWWFormUrlencodedDecoder) Decode(rawData []byte) (map[string]any, error) {
	values, err := url.ParseQuery(stringx.ToString(rawData))
	if err != nil {
		return nil, err
	}

	result := make(map[string]any, len(values))
	for k, v := range values {
		result[k] = v
	}

	return result, nil
}
