// Copyright 2026 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package httpcache

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
)

type keyHash struct {
	hash hash.Hash
}

func newKeyHash(domain string) *keyHash {
	result := &keyHash{hash: sha256.New()}
	result.writeString(cacheKeyNamespace)
	result.writeString(domain)

	return result
}

func (key *keyHash) writeBool(value bool) {
	if value {
		key.writeUint64(1)
	} else {
		key.writeUint64(0)
	}
}

func (key *keyHash) writeUint64(value uint64) {
	var data [8]byte
	binary.BigEndian.PutUint64(data[:], value)

	_, _ = key.hash.Write(data[:])
}

func (key *keyHash) writeString(value string) {
	key.writeUint64(uint64(len(value)))

	_, _ = key.hash.Write([]byte(value))
}

func (key *keyHash) sum() string {
	return hex.EncodeToString(key.hash.Sum(nil))
}
