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

package cachekey

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"net/http"
	"slices"

	"github.com/dadrus/heimdall/internal/x/stringx"
)

const namespace = "heimdall-cache-key:v1"

type Builder struct {
	hash hash.Hash
}

func New(domain string) *Builder {
	result := &Builder{hash: sha256.New()}

	result.WriteString(namespace)
	result.WriteString(domain)

	return result
}

func (key *Builder) WriteBool(value bool) {
	if value {
		key.WriteUint64(1)
	} else {
		key.WriteUint64(0)
	}
}

func (key *Builder) WriteUint64(value uint64) {
	var data [8]byte
	binary.BigEndian.PutUint64(data[:], value)

	_, _ = key.hash.Write(data[:])
}

func (key *Builder) WriteInt64(value int64) {
	key.WriteUint64(uint64(value)) //nolint:gosec
}

func (key *Builder) WriteString(value string) {
	key.WriteUint64(uint64(len(value)))

	_, _ = key.hash.Write(stringx.ToBytes(value))
}

func (key *Builder) WriteBytes(value []byte) {
	key.WriteUint64(uint64(len(value)))

	_, _ = key.hash.Write(value)
}

func (key *Builder) WriteStrings(values []string) {
	key.WriteUint64(uint64(len(values)))

	for _, value := range values {
		key.WriteString(value)
	}
}

func (key *Builder) WriteHeader(header http.Header) {
	names := make([]string, 0, len(header))

	for name := range header {
		names = append(names, name)
	}

	slices.Sort(names)

	key.WriteUint64(uint64(len(names)))

	for _, name := range names {
		key.WriteString(name)
		key.WriteStrings(header[name])
	}
}

func (key *Builder) Sum() []byte {
	return key.hash.Sum(nil)
}

func (key *Builder) SumString() string {
	return hex.EncodeToString(key.Sum())
}
