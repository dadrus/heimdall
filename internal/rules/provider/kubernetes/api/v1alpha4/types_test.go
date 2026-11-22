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

package v1alpha4

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/rules/config"
)

func TestRuleSetSpecDeepCopy(t *testing.T) {
	t.Parallel()

	forwardHostHeader := true
	in := &RuleSetSpec{
		Rules: []config.Rule{
			{
				ID:      "with-backend",
				Matcher: config.Matcher{Routes: []config.Route{{Path: "/protected"}}},
				Backend: &config.Backend{
					Host:              "backend.example.com",
					ForwardHostHeader: &forwardHostHeader,
					URLRewriter: &config.URLRewriter{
						Scheme:              "https",
						QueryParamsToRemove: []string{"secret", "other"},
					},
				},
			},
			{ID: "without-backend", Matcher: config.Matcher{Routes: []config.Route{{Path: "/open"}}}},
		},
	}

	out := in.DeepCopy()

	require.Equal(t, in, out)
	require.NotSame(t, &in.Rules[0], &out.Rules[0])
	require.NotSame(t, in.Rules[0].Backend, out.Rules[0].Backend)
	require.NotSame(t, in.Rules[0].Backend.ForwardHostHeader, out.Rules[0].Backend.ForwardHostHeader)
	require.NotSame(t, in.Rules[0].Backend.URLRewriter, out.Rules[0].Backend.URLRewriter)
	require.Nil(t, out.Rules[1].Backend)

	out.Rules[0].Backend.Host = "changed.example.com"
	*out.Rules[0].Backend.ForwardHostHeader = false
	out.Rules[0].Backend.URLRewriter.QueryParamsToRemove[0] = "changed"
	assert.Equal(t, "backend.example.com", in.Rules[0].Backend.Host)
	assert.True(t, *in.Rules[0].Backend.ForwardHostHeader)
	assert.Equal(t, "secret", in.Rules[0].Backend.URLRewriter.QueryParamsToRemove[0])
}
