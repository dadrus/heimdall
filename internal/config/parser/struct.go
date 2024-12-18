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

package parser

import (
	"unicode"

	"github.com/knadh/koanf/providers/structs"
	"github.com/knadh/koanf/v2"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

func koanfFromStruct(conf any) (*koanf.Koanf, error) {
	parser := koanf.New(".")

	err := parser.Load(structs.Provider(conf, "koanf"), nil)
	if err != nil {
		return nil, err
	}

	keys := parser.Keys()
	// Assert all keys are lowercase
	for i := range keys {
		if !isLower(keys[i]) {
			return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
				"field %s does not have lowercase key, use the `koanf` tag", keys[i])
		}
	}

	return parser, nil
}

func isLower(s string) bool {
	for _, r := range s {
		if !unicode.IsLower(r) && unicode.IsLetter(r) {
			return false
		}
	}

	return true
}
