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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/config"
)

func TestRuleConfigDeepCopyInto(t *testing.T) {
	t.Parallel()

	// GIVEN
	var out Rule

	in := Rule{
		ID: "foo",
		Matcher: Matcher{
			Path:    "bar",
			Methods: []string{"GET", "PATCH"},
			With: MatcherConstraints{
				Scheme:    "https",
				HostGlob:  "**.example.com",
				HostRegex: ".*\\.example.com",
				PathGlob:  "**.css",
				PathRegex: ".*\\.css",
			},
		},
		Backend: &Backend{
			Host: "baz",
			URLRewriter: &URLRewriter{
				Scheme:              "http",
				PathPrefixToCut:     "/foo",
				PathPrefixToAdd:     "/bar",
				QueryParamsToRemove: []string{"baz"},
			},
		},
		Execute:      []config.MechanismConfig{{"foo": "bar"}},
		ErrorHandler: []config.MechanismConfig{{"bar": "foo"}},
	}

	// WHEN
	in.DeepCopyInto(&out)

	// THEN
	assert.Equal(t, in.ID, out.ID)
	assert.Equal(t, in.Matcher.Path, out.Matcher.Path)
	assert.Equal(t, in.Matcher.Methods, out.Matcher.Methods)
	assert.Equal(t, in.Matcher.With.Scheme, out.Matcher.With.Scheme)
	assert.Equal(t, in.Matcher.With.HostGlob, out.Matcher.With.HostGlob)
	assert.Equal(t, in.Matcher.With.HostRegex, out.Matcher.With.HostRegex)
	assert.Equal(t, in.Matcher.With.PathGlob, out.Matcher.With.PathGlob)
	assert.Equal(t, in.Matcher.With.PathRegex, out.Matcher.With.PathRegex)
	assert.Equal(t, in.Backend, out.Backend)
	assert.Equal(t, in.Execute, out.Execute)
	assert.Equal(t, in.ErrorHandler, out.ErrorHandler)
}

func TestRuleConfigDeepCopy(t *testing.T) {
	t.Parallel()

	// GIVEN
	in := Rule{
		ID: "foo",
		Matcher: Matcher{
			Path:    "bar",
			Methods: []string{"GET", "PATCH"},
			With: MatcherConstraints{
				Scheme:    "https",
				HostGlob:  "**.example.com",
				HostRegex: ".*\\.example.com",
				PathGlob:  "**.css",
				PathRegex: ".*\\.css",
			},
		},
		Backend: &Backend{
			Host: "baz",
			URLRewriter: &URLRewriter{
				Scheme:              "http",
				PathPrefixToCut:     "/foo",
				PathPrefixToAdd:     "/bar",
				QueryParamsToRemove: []string{"baz"},
			},
		},
		Execute:      []config.MechanismConfig{{"foo": "bar"}},
		ErrorHandler: []config.MechanismConfig{{"bar": "foo"}},
	}

	// WHEN
	out := in.DeepCopy()

	// THEN
	// different addresses
	require.NotSame(t, &in, out)

	// but same contents
	assert.Equal(t, in.ID, out.ID)
	assert.Equal(t, in.Matcher.Path, out.Matcher.Path)
	assert.Equal(t, in.Matcher.Methods, out.Matcher.Methods)
	assert.Equal(t, in.Matcher.With.Scheme, out.Matcher.With.Scheme)
	assert.Equal(t, in.Matcher.With.HostGlob, out.Matcher.With.HostGlob)
	assert.Equal(t, in.Matcher.With.HostRegex, out.Matcher.With.HostRegex)
	assert.Equal(t, in.Matcher.With.PathGlob, out.Matcher.With.PathGlob)
	assert.Equal(t, in.Matcher.With.PathRegex, out.Matcher.With.PathRegex)
	assert.Equal(t, in.Backend, out.Backend)
	assert.Equal(t, in.Execute, out.Execute)
	assert.Equal(t, in.ErrorHandler, out.ErrorHandler)
}
