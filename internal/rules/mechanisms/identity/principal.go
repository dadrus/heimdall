// Copyright 2025 Dimitrij Drus <dadrus@gmx.de>
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

package identity

import (
	"crypto/sha256"
	"encoding/json"

	"github.com/dadrus/heimdall/internal/x/stringx"
)

type Principal struct {
	ID         string
	Attributes map[string]any

	// cached hash value
	hash []byte
}

func (s *Principal) Hash() []byte {
	if s.hash != nil {
		return s.hash
	}

	hash := sha256.New()

	if len(s.Attributes) != 0 {
		_ = json.NewEncoder(hash).Encode(s)
	} else {
		hash.Write(stringx.ToBytes(s.ID))
	}

	var result [sha256.Size]byte

	s.hash = hash.Sum(result[:0])

	return s.hash
}
