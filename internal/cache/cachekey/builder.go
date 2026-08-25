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

func (b *Builder) WriteBool(value bool) {
	if value {
		b.WriteUint64(1)
	} else {
		b.WriteUint64(0)
	}
}

func (b *Builder) WriteUint64(value uint64) {
	var data [8]byte
	binary.BigEndian.PutUint64(data[:], value)

	_, _ = b.hash.Write(data[:])
}

func (b *Builder) WriteInt64(value int64) {
	b.WriteUint64(uint64(value)) //nolint:gosec
}

func (b *Builder) WriteString(value string) {
	b.WriteUint64(uint64(len(value)))

	_, _ = b.hash.Write(stringx.ToBytes(value))
}

func (b *Builder) WriteBytes(value []byte) {
	b.WriteUint64(uint64(len(value)))

	_, _ = b.hash.Write(value)
}

func (b *Builder) WriteStrings(values []string) {
	b.WriteUint64(uint64(len(values)))

	for _, value := range values {
		b.WriteString(value)
	}
}

func (b *Builder) WriteHeader(header http.Header) {
	names := make([]string, 0, len(header))

	for name := range header {
		names = append(names, name)
	}

	slices.Sort(names)

	b.WriteUint64(uint64(len(names)))

	for _, name := range names {
		b.WriteString(name)
		b.WriteStrings(header[name])
	}
}

func (b *Builder) Sum() []byte {
	return b.hash.Sum(nil)
}

func (b *Builder) SumString() string {
	return hex.EncodeToString(b.Sum())
}
