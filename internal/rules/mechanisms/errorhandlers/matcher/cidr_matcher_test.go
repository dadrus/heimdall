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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateNewCIDRMatcherUsingProperCIDRValues(t *testing.T) {
	// GIVEN
	cidrs := []string{
		"192.168.1.0/24",
		"10.10.0.0/16",
	}

	// WHEN
	matcher, err := NewCIDRMatcher(cidrs)

	// THEN
	require.NoError(t, err)
	assert.NotNil(t, matcher)
}

func TestCreateNewCIDRMatcherUsingBadCIDRValues(t *testing.T) {
	// GIVEN
	cidrs := []string{
		"192.168.1.0/foo",
		"10.10.0.0/16",
	}

	// WHEN
	matcher, err := NewCIDRMatcher(cidrs)

	// THEN
	require.Error(t, err)
	assert.Nil(t, matcher)
}

func TestCIDRMatcherMatchIPsInTheRange(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc       string
		cidrs    []string
		ips      []string
		matching bool
	}{
		{
			uc:       "match ips in the range",
			cidrs:    []string{"192.168.1.0/24", "10.10.0.0/16"},
			ips:      []string{"192.168.1.10", "10.10.20.124"},
			matching: true,
		},
		{
			uc:       "don't match ips out of range",
			cidrs:    []string{"192.168.1.0/24", "10.10.0.0/16"},
			ips:      []string{"192.168.2.10", "10.11.20.124"},
			matching: false,
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			matcher, err := NewCIDRMatcher(tc.cidrs)
			require.NoError(t, err)

			// WHEN
			matched := matcher.Match(tc.ips...)

			// THEN
			assert.Equal(t, tc.matching, matched)
		})
	}
}
