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

package httpendpoint

import (
	"github.com/go-viper/mapstructure/v2"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/endpoint"
	"github.com/dadrus/heimdall/internal/rules/endpoint/authstrategy"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

func decodeConfig(app app.Context, input any, output any) error {
	dec, err := mapstructure.NewDecoder(
		&mapstructure.DecoderConfig{
			DecodeHook: mapstructure.ComposeDecodeHookFunc(
				authstrategy.DecodeAuthenticationStrategyHookFunc(app),
				endpoint.DecodeEndpointHookFunc(),
				mapstructure.StringToTimeDurationHookFunc(),
			),
			Result:      output,
			ErrorUnused: true,
		})
	if err != nil {
		return errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"failed decoding http_endpoint rule provider config").CausedBy(err)
	}

	if err = dec.Decode(input); err != nil {
		return errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"failed decoding http_endpoint rule provider config").CausedBy(err)
	}

	if err = app.Validator().ValidateStruct(output); err != nil {
		return errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"failed validating http_endpoint rule provider config").CausedBy(err)
	}

	return nil
}
