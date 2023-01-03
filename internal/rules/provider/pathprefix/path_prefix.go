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

package pathprefix

import (
	"strings"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type PathPrefix string

func (p PathPrefix) Verify(rules []rule.Configuration) error {
	if len(p) == 0 {
		return nil
	}

	for _, rule := range rules {
		if strings.HasPrefix(rule.RuleMatcher.URL, "/") &&
			// only path is specified
			!strings.HasPrefix(rule.RuleMatcher.URL, string(p)) ||
			// patterns are specified before the path
			// There should be a better way to check it
			!strings.Contains(rule.RuleMatcher.URL, string(p)) {
			return errorchain.NewWithMessage(heimdall.ErrConfiguration,
				"path prefix validation failed for rule ID=%s")
		}
	}

	return nil
}
