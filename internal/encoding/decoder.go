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

package encoding

import (
	"bytes"
	"errors"
	"io"

	"github.com/drone/envsubst/v2"
	"github.com/go-viper/mapstructure/v2"
	"gopkg.in/yaml.v3"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

type Decoder struct {
	decoderOpts
}

func NewDecoder(opts ...DecoderOption) *Decoder {
	decoder := &Decoder{
		decoderOpts: decoderOpts{
			validator: noopValidator{},
			tagName:   "json",
		},
	}

	for _, opt := range opts {
		opt(&decoder.decoderOpts)
	}

	return decoder
}

func (d *Decoder) Decode(out any, reader io.Reader) error {
	var rawConfig map[string]any

	if d.contentType != "application/json" && d.contentType != "application/yaml" {
		return errorchain.NewWithMessagef(heimdall.ErrInternal,
			"unsupported content type: %s", d.contentType)
	}

	if d.substituteEnvVars {
		raw, err := io.ReadAll(reader)
		if err != nil {
			return errorchain.NewWithMessage(heimdall.ErrInternal,
				"reading object failed").CausedBy(err)
		}

		content, err := envsubst.EvalEnv(stringx.ToString(raw))
		if err != nil {
			return errorchain.NewWithMessage(heimdall.ErrConfiguration,
				"substitution of environment variables failed").CausedBy(err)
		}

		reader = bytes.NewReader(stringx.ToBytes(content))
	}

	dec := yaml.NewDecoder(reader)
	if err := dec.Decode(&rawConfig); err != nil {
		if errors.Is(err, io.EOF) {
			return err
		}

		return errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"parsing of object failed").CausedBy(err)
	}

	return d.DecodeMap(out, rawConfig)
}

func (d *Decoder) DecodeMap(out any, in map[string]any) error {
	dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:      out,
		ErrorUnused: d.errorOnUnused,
		TagName:     d.tagName,
		DecodeHook:  x.IfThenElse(d.decodeHooks != nil, d.decodeHooks, mapstructure.ComposeDecodeHookFunc()),
	})
	if err != nil {
		return errorchain.NewWithMessage(heimdall.ErrInternal,
			"failed creating object decoder").CausedBy(err)
	}

	if err = dec.Decode(in); err != nil {
		return errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"decoding of object failed").CausedBy(err)
	}

	if err = d.validator.Validate(out); err != nil {
		return errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"object validation failed").CausedBy(err)
	}

	return nil
}
