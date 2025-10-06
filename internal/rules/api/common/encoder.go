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

package common

import (
	"io"

	"github.com/goccy/go-json"
	"gopkg.in/yaml.v3"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type Encoder[T any] struct {
	encoderOpts
}

func NewEncoder[T any](opts ...EncoderOption) *Encoder[T] {
	encoder := &Encoder[T]{}

	for _, opt := range opts {
		opt(&encoder.encoderOpts)
	}

	return encoder
}

func (d *Encoder[T]) Encode(obj T, out io.Writer) error {
	var err error

	switch d.contentType {
	case "application/json":
		err = json.NewEncoder(out).Encode(obj)
	case "application/yaml":
		err = yaml.NewEncoder(out).Encode(obj)
	default:
		return errorchain.NewWithMessagef(heimdall.ErrInternal,
			"unsupported content type: %s", d.contentType)
	}

	if err != nil {
		return errorchain.NewWithMessage(heimdall.ErrInternal,
			"marshalling object failed")
	}

	return nil
}
