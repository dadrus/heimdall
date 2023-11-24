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

package matcher

import (
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x"
)

type ErrorConditionMatcher struct {
	Error   *ErrorMatcher  `mapstructure:"error"`
	CIDR    *CIDRMatcher   `mapstructure:"request_cidr"`
	Headers *HeaderMatcher `mapstructure:"request_headers"`
}

func (ecm ErrorConditionMatcher) Match(ctx heimdall.Context, err error) bool {
	errorMatched := x.IfThenElseExec(ecm.Error != nil,
		func() bool { return ecm.Error.Match(err) },
		func() bool { return true })

	ipMatched := x.IfThenElseExec(ecm.CIDR != nil,
		func() bool { return ecm.CIDR.Match(ctx.Request().ClientIPAddresses...) },
		func() bool { return true })

	headerMatched := x.IfThenElseExec(ecm.Headers != nil,
		func() bool { return ecm.Headers.Match(ctx.Request().Headers()) },
		func() bool { return true })

	return errorMatched && ipMatched && headerMatched
}
