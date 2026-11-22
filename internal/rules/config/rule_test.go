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

	trueValue := true

	// GIVEN
	var out Rule

	in := Rule{
		ID: "foo",
		Matcher: Matcher{
			Routes: []Route{
				{
					Path: "/:foo/*something",
					PathParams: []ParameterMatcher{
						{Name: "foo", Value: "bar", Type: "glob"},
						{Name: "something", Value: ".*\\.css", Type: "regex"},
					},
				},
				{
					Path: "/some/static/path",
				},
			},
			BacktrackingEnabled: &trueValue,
			Scheme:              "https",
			Hosts: []HostMatcher{
				{
					Value: "**.example.com",
					Type:  "glob",
				},
			},
			Methods: []string{"GET", "PATCH"},
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
	assert.Equal(t, in, out)
	require.NotSame(t, in.Backend, out.Backend)
	require.NotSame(t, in.Backend.URLRewriter, out.Backend.URLRewriter)

	out.Backend.Host = "changed"
	out.Backend.URLRewriter.QueryParamsToRemove[0] = "changed"
	assert.Equal(t, "baz", in.Backend.Host)
	assert.Equal(t, "baz", in.Backend.URLRewriter.QueryParamsToRemove[0])
}

func TestRuleConfigDeepCopy(t *testing.T) {
	t.Parallel()

	// GIVEN
	forwardHostHeader := true

	in := &Rule{
		ID: "foo",
		Matcher: Matcher{
			Routes: []Route{
				{
					Path: "/:foo/*something",
					PathParams: []ParameterMatcher{
						{Name: "foo", Value: "bar", Type: "glob"},
						{Name: "something", Value: ".*\\.css", Type: "regex"},
					},
				},
				{
					Path: "/some/static/path",
				},
			},
			Scheme: "https",
			Hosts: []HostMatcher{
				{
					Value: "**.example.com",
					Type:  "glob",
				},
			},
			Methods: []string{"GET", "PATCH"},
		},
		Backend: &Backend{
			Host:              "baz",
			ForwardHostHeader: &forwardHostHeader,
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
	require.NotSame(t, in, out)

	// but same contents
	assert.Equal(t, in, out)
	require.NotSame(t, in.Backend, out.Backend)
	require.NotSame(t, in.Backend.ForwardHostHeader, out.Backend.ForwardHostHeader)
	require.NotSame(t, in.Backend.URLRewriter, out.Backend.URLRewriter)

	// Changing the copy must not change the original configuration.
	out.Backend.Host = "changed"
	*out.Backend.ForwardHostHeader = false
	out.Backend.URLRewriter.Scheme = "https"
	out.Backend.URLRewriter.QueryParamsToRemove[0] = "changed"
	assert.Equal(t, "baz", in.Backend.Host)
	assert.True(t, *in.Backend.ForwardHostHeader)
	assert.Equal(t, "http", in.Backend.URLRewriter.Scheme)
	assert.Equal(t, "baz", in.Backend.URLRewriter.QueryParamsToRemove[0])
}
