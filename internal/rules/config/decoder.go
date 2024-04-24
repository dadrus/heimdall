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

package config

import (
	"github.com/go-viper/mapstructure/v2"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/validation"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

func DecodeConfig(input any, output any) error {
	dec, err := mapstructure.NewDecoder(
		&mapstructure.DecoderConfig{
			DecodeHook: mapstructure.ComposeDecodeHookFunc(
				mapstructure.StringToTimeDurationHookFunc(),
			),
			Result:      output,
			ErrorUnused: true,
			TagName:     "json",
		})
	if err != nil {
		return err
	}

	if err = dec.Decode(input); err != nil {
		return errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"failed decoding ruleset config").CausedBy(err)
	}

	if err = validation.ValidateStruct(output); err != nil {
		return errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"failed validating ruleset config").CausedBy(err)
	}

	return nil
}
