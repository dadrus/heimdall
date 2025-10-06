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
	"bytes"
	"errors"
	"io"

	"github.com/drone/envsubst/v2"
	"github.com/go-viper/mapstructure/v2"
	"gopkg.in/yaml.v3"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

type Decoder[T any] struct {
	decoderOpts
}

func NewDecoder[T any](opts ...DecoderOption) *Decoder[T] {
	decoder := &Decoder[T]{
		decoderOpts: decoderOpts{
			validator: noopValidator{},
		},
	}

	for _, opt := range opts {
		opt(&decoder.decoderOpts)
	}

	return decoder
}

func (d *Decoder[T]) Decode(reader io.Reader) (T, error) {
	var (
		res       T
		rawConfig map[string]any
	)

	if d.contentType != "application/json" && d.contentType != "application/yaml" {
		return res, errorchain.NewWithMessagef(heimdall.ErrInternal,
			"unsupported content type: %s", d.contentType)
	}

	if d.substituteEnvVars {
		raw, err := io.ReadAll(reader)
		if err != nil {
			return res, errorchain.NewWithMessage(heimdall.ErrInternal,
				"reading object failed").CausedBy(err)
		}

		content, err := envsubst.EvalEnv(stringx.ToString(raw))
		if err != nil {
			return res, errorchain.NewWithMessage(heimdall.ErrConfiguration,
				"substitution of environment variables failed").CausedBy(err)
		}

		reader = bytes.NewReader(stringx.ToBytes(content))
	}

	dec := yaml.NewDecoder(reader)
	if err := dec.Decode(&rawConfig); err != nil {
		if errors.Is(err, io.EOF) {
			return res, err
		}

		return res, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"parsing of object failed").CausedBy(err)
	}

	mdec, err := mapstructure.NewDecoder(
		&mapstructure.DecoderConfig{
			DecodeHook: mapstructure.ComposeDecodeHookFunc(
				mapstructure.StringToTimeDurationHookFunc(),
			),
			Result:      &res,
			ErrorUnused: d.errorOnUnused,
			TagName:     "json",
		})
	if err != nil {
		return res, errorchain.NewWithMessage(heimdall.ErrInternal,
			"failed creating object decoder").CausedBy(err)
	}

	if err = mdec.Decode(rawConfig); err != nil {
		return res, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"decoding of object failed").CausedBy(err)
	}

	if err = d.validator.Validate(res); err != nil {
		return res, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"object validation failed").CausedBy(err)
	}

	return res, nil
}
