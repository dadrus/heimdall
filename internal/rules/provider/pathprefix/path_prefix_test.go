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
	"testing"

	"github.com/stretchr/testify/require"

	event2 "github.com/dadrus/heimdall/internal/rules/rule"
)

func TestPathPrefixVerify(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		prefix PathPrefix
		url    string
		fail   bool
	}{
		{uc: "path only and without required prefix", prefix: "/foo/bar", url: "/bar/foo/moo", fail: true},
		{uc: "path only with required prefix", prefix: "/foo/bar", url: "/foo/bar/moo", fail: false},
		{uc: "full url and without required prefix", prefix: "/foo/bar", url: "https://<**>/bar/foo/moo", fail: true},
		{uc: "full url with required prefix", prefix: "/foo/bar", url: "https://<**>/foo/bar/moo", fail: false},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// WHEN
			err := tc.prefix.Verify([]event2.Configuration{{RuleMatcher: event2.Matcher{URL: tc.url}}})

			if tc.fail {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
