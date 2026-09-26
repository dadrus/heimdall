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

package httpx

import "strings"

type headerBuilder struct {
	prefix string
	parts  []string
}

func NewHeader(options ...Option) string {
	h := headerBuilder{}
	for _, opt := range options {
		opt(&h)
	}

	return h.build()
}

func (b headerBuilder) build() string {
	return b.prefix + strings.Join(b.parts, ", ")
}

type Option func(*headerBuilder)

func WithPrefix(value string) Option {
	return func(builder *headerBuilder) {
		if len(value) != 0 {
			builder.prefix = value + " "
		}
	}
}

func WithKeyValue(key, value string) Option {
	return func(builder *headerBuilder) {
		if len(key) != 0 && len(value) != 0 {
			builder.parts = append(builder.parts, key+"=\""+value+"\"")
		}
	}
}

func WithValue(value string) Option {
	return func(builder *headerBuilder) {
		if len(value) != 0 {
			builder.parts = append(builder.parts, value)
		}
	}
}
