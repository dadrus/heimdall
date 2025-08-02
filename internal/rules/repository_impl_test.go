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

package rules

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	mocks2 "github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/rules/config"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/rules/rule/mocks"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/radixtrie"
)

func TestRepositoryAddRuleSet(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		initRules []rule.Rule
		tbaRules  []rule.Rule
		assert    func(t *testing.T, err error, repo *repository)
	}{
		"rule with multiple routes from the same rule set can be added": {
			initRules: func() []rule.Rule {
				rul := &ruleImpl{id: "1", srcID: "1"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "example.com", path: "/1/:some"})
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "example.com", path: "/1/2"})
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "example.com", path: "/1/3/**"})
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "example.com", path: "/1/3/:some"})
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "example.com", path: "/1/3/4"})
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "example.com", path: "/1/3/5/6"})
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "*.example.com", path: "/1/3/5/6"})
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "*", path: "/**"})

				return []rule.Rule{rul}
			}(),
			assert: func(t *testing.T, err error, repo *repository) {
				t.Helper()

				require.NoError(t, err)
				assert.Len(t, repo.knownRules, 1)
				assert.False(t, repo.index.Empty())

				_, err = repo.index.FindEntry("example.com", "/1/1",
					radixtrie.LookupMatcherFunc[rule.Route](
						func(_ rule.Route, _, _ []string) bool { return true }))
				require.NoError(t, err)
				_, err = repo.index.FindEntry("example.com", "/1/2",
					radixtrie.LookupMatcherFunc[rule.Route](
						func(_ rule.Route, _, _ []string) bool { return true }))
				require.NoError(t, err)
				_, err = repo.index.FindEntry("example.com", "/1/3",
					radixtrie.LookupMatcherFunc[rule.Route](
						func(_ rule.Route, _, _ []string) bool { return true }))
				require.NoError(t, err)
				_, err = repo.index.FindEntry("example.com", "/1/3/6/7",
					radixtrie.LookupMatcherFunc[rule.Route](
						func(_ rule.Route, _, _ []string) bool { return true }))
				require.NoError(t, err)
				_, err = repo.index.FindEntry("example.com", "/1/3/5",
					radixtrie.LookupMatcherFunc[rule.Route](
						func(_ rule.Route, _, _ []string) bool { return true }))
				require.NoError(t, err)
				_, err = repo.index.FindEntry("example.com", "/1/3/4",
					radixtrie.LookupMatcherFunc[rule.Route](
						func(_ rule.Route, _, _ []string) bool { return true }))
				require.NoError(t, err)
				_, err = repo.index.FindEntry("example.com", "/1/3/5/6",
					radixtrie.LookupMatcherFunc[rule.Route](
						func(_ rule.Route, _, _ []string) bool { return true }))
				require.NoError(t, err)
			},
		},
		"adding rules matching example.com/1/1 and example.com/2/1 defined in different rulesets is fine": {
			initRules: func() []rule.Rule {
				rul := &ruleImpl{id: "1", srcID: "1"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "example.com", path: "/1/1"})

				return []rule.Rule{rul}
			}(),
			tbaRules: func() []rule.Rule {
				rul := &ruleImpl{id: "2", srcID: "2"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "example.com", path: "/2/1"})

				return []rule.Rule{rul}
			}(),
			assert: func(t *testing.T, err error, _ *repository) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"rule from one ruleset cannot be overridden by a rule with the same matching expressions from another ruleset": {
			initRules: func() []rule.Rule {
				rul := &ruleImpl{id: "1", srcID: "1"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "example.com", path: "/1/1"})

				return []rule.Rule{rul}
			}(),
			tbaRules: func() []rule.Rule {
				rul := &ruleImpl{id: "2", srcID: "2"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "example.com", path: "/1/1"})

				return []rule.Rule{rul}
			}(),
			assert: func(t *testing.T, err error, _ *repository) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "conflicting rules")
			},
		},
		"adding a route with wildcard at the path start from another ruleset is not possible": {
			initRules: func() []rule.Rule {
				rul := &ruleImpl{id: "1", srcID: "1"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "example.com", path: "/1/1"})

				return []rule.Rule{rul}
			}(),
			tbaRules: func() []rule.Rule {
				rul := &ruleImpl{id: "2", srcID: "2"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "example.com", path: "/:some/1"})

				return []rule.Rule{rul}
			}(),
			assert: func(t *testing.T, err error, _ *repository) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "conflicting rules")
			},
		},
		"adding a route with more specific host from another ruleset is not possible": {
			initRules: func() []rule.Rule {
				rul := &ruleImpl{id: "1", srcID: "1"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "*", path: "/1/1"})

				return []rule.Rule{rul}
			}(),
			tbaRules: func() []rule.Rule {
				rul := &ruleImpl{id: "2", srcID: "2"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "example.com", path: "/1/1"})

				return []rule.Rule{rul}
			}(),
			assert: func(t *testing.T, err error, _ *repository) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "conflicting rules")
			},
		},
		"adding rules matching * for host and /1/1 for path and example.com/2/1 defined in different rulesets is fine": {
			initRules: func() []rule.Rule {
				rul := &ruleImpl{id: "1", srcID: "1"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "*", path: "/1/1"})

				return []rule.Rule{rul}
			}(),
			tbaRules: func() []rule.Rule {
				rul := &ruleImpl{id: "2", srcID: "2"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "example.com", path: "/2/1"})

				return []rule.Rule{rul}
			}(),
			assert: func(t *testing.T, err error, _ *repository) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"adding a route with wildcard at the path end from another ruleset is not possible": {
			initRules: func() []rule.Rule {
				rul := &ruleImpl{id: "1", srcID: "1"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "example.com", path: "/1/1"})

				return []rule.Rule{rul}
			}(),
			tbaRules: func() []rule.Rule {
				rul := &ruleImpl{id: "2", srcID: "2"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "example.com", path: "/1/:some"})

				return []rule.Rule{rul}
			}(),
			assert: func(t *testing.T, err error, _ *repository) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "conflicting rules")
			},
		},
		"adding rules matching example.com/1/1 and example.com/2/:some defined in different rulesets is fine": {
			initRules: func() []rule.Rule {
				rul := &ruleImpl{id: "1", srcID: "1"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "example.com", path: "/1/1"})

				return []rule.Rule{rul}
			}(),
			tbaRules: func() []rule.Rule {
				rul := &ruleImpl{id: "2", srcID: "2"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "example.com", path: "/2/:some"})

				return []rule.Rule{rul}
			}(),
			assert: func(t *testing.T, err error, _ *repository) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"adding a route with free wildcard at the path end from another ruleset is not possible": {
			initRules: func() []rule.Rule {
				rul := &ruleImpl{id: "1", srcID: "1"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "example.com", path: "/1/1"})

				return []rule.Rule{rul}
			}(),
			tbaRules: func() []rule.Rule {
				rul := &ruleImpl{id: "2", srcID: "2"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "example.com", path: "/1/**"})

				return []rule.Rule{rul}
			}(),
			assert: func(t *testing.T, err error, _ *repository) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "conflicting rules")
			},
		},
		"adding rules matching example.com/1/1 and example.com/2/* defined in different rulesets is fine": {
			initRules: func() []rule.Rule {
				rul := &ruleImpl{id: "1", srcID: "1"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "example.com", path: "/1/1"})

				return []rule.Rule{rul}
			}(),
			tbaRules: func() []rule.Rule {
				rul := &ruleImpl{id: "2", srcID: "2"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "example.com", path: "/2/**"})

				return []rule.Rule{rul}
			}(),
			assert: func(t *testing.T, err error, _ *repository) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"adding a route with free wildcards at the path end and in the host from another ruleset is not possible": {
			initRules: func() []rule.Rule {
				rul := &ruleImpl{id: "1", srcID: "1"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "foo.example.com", path: "/1/2/3"})

				return []rule.Rule{rul}
			}(),
			tbaRules: func() []rule.Rule {
				rul := &ruleImpl{id: "2", srcID: "2"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "*.example.com", path: "/1/**"})

				return []rule.Rule{rul}
			}(),
			assert: func(t *testing.T, err error, _ *repository) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "conflicting rules")
			},
		},
		"adding rules matching foo.example.com/1/2/3 and *.example.com/2/** defined in different rulesets is fine": {
			initRules: func() []rule.Rule {
				rul := &ruleImpl{id: "1", srcID: "1"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "foo.example.com", path: "/1/2/3"})

				return []rule.Rule{rul}
			}(),
			tbaRules: func() []rule.Rule {
				rul := &ruleImpl{id: "2", srcID: "2"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "*.example.com", path: "/2/**"})

				return []rule.Rule{rul}
			}(),
			assert: func(t *testing.T, err error, _ *repository) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"rule matching foo.example.com/1/2/3 from one ruleset cannot be overridden by a rule matching *.example.com/1/:2/3 from another ruleset": {
			initRules: func() []rule.Rule {
				rul := &ruleImpl{id: "1", srcID: "1"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "foo.example.com", path: "/1/2/3"})

				return []rule.Rule{rul}
			}(),
			tbaRules: func() []rule.Rule {
				rul := &ruleImpl{id: "2", srcID: "2"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "*.example.com", path: "/1/:2/3"})

				return []rule.Rule{rul}
			}(),
			assert: func(t *testing.T, err error, _ *repository) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "conflicting rules")
			},
		},
		"rule matching foo.example.com/1/:2/3 from one ruleset cannot be overridden by a rule matching *.example.com/1/** from another ruleset": {
			initRules: func() []rule.Rule {
				rul := &ruleImpl{id: "1", srcID: "1"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "foo.example.com", path: "/1/:2/3"})

				return []rule.Rule{rul}
			}(),
			tbaRules: func() []rule.Rule {
				rul := &ruleImpl{id: "2", srcID: "2"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "*.example.com", path: "/1/**"})

				return []rule.Rule{rul}
			}(),
			assert: func(t *testing.T, err error, _ *repository) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "conflicting rules")
			},
		},
		"adding rules matching foo.example.com/1/:2/3 and *.example.com/1/2/3 defined in different rulesets is not possible": {
			initRules: func() []rule.Rule {
				rul := &ruleImpl{id: "1", srcID: "1"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "foo.example.com", path: "/1/:2/3"})

				return []rule.Rule{rul}
			}(),
			tbaRules: func() []rule.Rule {
				rul := &ruleImpl{id: "2", srcID: "2"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "*.example.com", path: "/1/2/3"})

				return []rule.Rule{rul}
			}(),
			assert: func(t *testing.T, err error, _ *repository) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "conflicting rules")
			},
		},
		"adding rules matching foo.example.com/1/2/:3 and *.example.com/1/2/3 defined in different rulesets is not possible": {
			initRules: func() []rule.Rule {
				rul := &ruleImpl{id: "1", srcID: "1"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "*.example.com", path: "/1/2/3"})

				return []rule.Rule{rul}
			}(),
			tbaRules: func() []rule.Rule {
				rul := &ruleImpl{id: "2", srcID: "2"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "foo.example.com", path: "/1/2/:3"})

				return []rule.Rule{rul}
			}(),
			assert: func(t *testing.T, err error, _ *repository) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "conflicting rules")
			},
		},
		"adding rules matching *.example.com/1/2/3 and foo.example.com/2/2/:3 defined in different rulesets is fine": {
			initRules: func() []rule.Rule {
				rul := &ruleImpl{id: "1", srcID: "1"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "*.example.com", path: "/1/2/3"})

				return []rule.Rule{rul}
			}(),
			tbaRules: func() []rule.Rule {
				rul := &ruleImpl{id: "2", srcID: "2"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "foo.example.com", path: "/2/2/:3"})

				return []rule.Rule{rul}
			}(),
			assert: func(t *testing.T, err error, _ *repository) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"adding rules matching foo.example.com/1/:2/:3 and *.example.com/1/2/3 defined in different rulesets is not possible": {
			initRules: func() []rule.Rule {
				rul := &ruleImpl{id: "1", srcID: "1"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "*.example.com", path: "/1/2/3"})

				return []rule.Rule{rul}
			}(),
			tbaRules: func() []rule.Rule {
				rul := &ruleImpl{id: "2", srcID: "2"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "foo.example.com", path: "/1/:2/:3"})

				return []rule.Rule{rul}
			}(),
			assert: func(t *testing.T, err error, _ *repository) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "conflicting rules")
			},
		},
		"adding rules matching foo.example.com/1/** and *.example.com/1/2/3 defined in different rulesets is not possible": {
			initRules: func() []rule.Rule {
				rul := &ruleImpl{id: "1", srcID: "1"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "*.example.com", path: "/1/2/3"})

				return []rule.Rule{rul}
			}(),
			tbaRules: func() []rule.Rule {
				rul := &ruleImpl{id: "2", srcID: "2"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "foo.example.com", path: "/1/**"})

				return []rule.Rule{rul}
			}(),
			assert: func(t *testing.T, err error, _ *repository) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "conflicting rules")
			},
		},
		"adding rules matching *.example.com/1/2/3 and foo.example.com/2/** defined in different rulesets is fine": {
			initRules: func() []rule.Rule {
				rul := &ruleImpl{id: "1", srcID: "1"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "*.example.com", path: "/1/2/3"})

				return []rule.Rule{rul}
			}(),
			tbaRules: func() []rule.Rule {
				rul := &ruleImpl{id: "2", srcID: "2"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "foo.example.com", path: "/2/**"})

				return []rule.Rule{rul}
			}(),
			assert: func(t *testing.T, err error, _ *repository) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"adding rules matching foo.example.com/** and *.example.com/1/2/3 defined in different rulesets is not possible": {
			initRules: func() []rule.Rule {
				rul := &ruleImpl{id: "1", srcID: "1"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "*.example.com", path: "/1/2/3"})

				return []rule.Rule{rul}
			}(),
			tbaRules: func() []rule.Rule {
				rul := &ruleImpl{id: "2", srcID: "2"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "foo.example.com", path: "/*"})

				return []rule.Rule{rul}
			}(),
			assert: func(t *testing.T, err error, _ *repository) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "conflicting rules")
			},
		},
		"overriding existing rule with wildcard in the host and at path end by a more specific rule from another rule set is not possible": {
			initRules: func() []rule.Rule {
				rul := &ruleImpl{id: "1", srcID: "1"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "*.example.com", path: "/1/:some"})

				return []rule.Rule{rul}
			}(),
			tbaRules: func() []rule.Rule {
				rul := &ruleImpl{id: "2", srcID: "2"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "foo.example.com", path: "/1/:some"})

				return []rule.Rule{rul}
			}(),
			assert: func(t *testing.T, err error, _ *repository) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "conflicting rules")
			},
		},
		"rule matching *.example.com/1/** defined in one ruleset cannot be overridden by a rule matching foo.example.com/1/** from another ruleset": {
			initRules: func() []rule.Rule {
				rul := &ruleImpl{id: "1", srcID: "1"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "*.example.com", path: "/1/**"})

				return []rule.Rule{rul}
			}(),
			tbaRules: func() []rule.Rule {
				rul := &ruleImpl{id: "2", srcID: "2"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "foo.example.com", path: "/1/**"})

				return []rule.Rule{rul}
			}(),
			assert: func(t *testing.T, err error, _ *repository) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "conflicting rules")
			},
		},
		"rule matching *.example.com/1/:some/3 defined in one ruleset cannot be overridden by a rule matching foo.example.com/1/:some/3 from another ruleset": {
			initRules: func() []rule.Rule {
				rul := &ruleImpl{id: "1", srcID: "1"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "*.example.com", path: "/1/:some/3"})

				return []rule.Rule{rul}
			}(),
			tbaRules: func() []rule.Rule {
				rul := &ruleImpl{id: "2", srcID: "2"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "foo.example.com", path: "/1/:some/3"})

				return []rule.Rule{rul}
			}(),
			assert: func(t *testing.T, err error, _ *repository) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "conflicting rules")
			},
		},
		"adding a route with free wildcard at the path start from another ruleset is not possible": {
			initRules: func() []rule.Rule {
				rul := &ruleImpl{id: "1", srcID: "1"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "example.com", path: "/1/1"})

				return []rule.Rule{rul}
			}(),
			tbaRules: func() []rule.Rule {
				rul := &ruleImpl{id: "2", srcID: "2"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "example.com", path: "/**"})

				return []rule.Rule{rul}
			}(),
			assert: func(t *testing.T, err error, _ *repository) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "conflicting rules")
			},
		},
		"adding a route with free wildcard at the path end from another ruleset for a rule starting with a wildcard is not possible": {
			initRules: func() []rule.Rule {
				rul := &ruleImpl{id: "1", srcID: "1"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "example.com", path: "/:some/1"})

				return []rule.Rule{rul}
			}(),
			tbaRules: func() []rule.Rule {
				rul := &ruleImpl{id: "2", srcID: "2"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "example.com", path: "/:some/**"})

				return []rule.Rule{rul}
			}(),
			assert: func(t *testing.T, err error, _ *repository) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "conflicting rules")
			},
		},
		"adding a route with free wildcard at the path start from another ruleset for a rule starting with a wildcard is not possible": {
			initRules: func() []rule.Rule {
				rul := &ruleImpl{id: "1", srcID: "1"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "example.com", path: "/:some/1"})

				return []rule.Rule{rul}
			}(),
			tbaRules: func() []rule.Rule {
				rul := &ruleImpl{id: "2", srcID: "2"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "example.com", path: "/**"})

				return []rule.Rule{rul}
			}(),
			assert: func(t *testing.T, err error, _ *repository) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "conflicting rules")
			},
		},
		"adding a route with free wildcard as host and at the path start from another ruleset for a rule starting with a wildcard is not possible": {
			initRules: func() []rule.Rule {
				rul := &ruleImpl{id: "1", srcID: "1"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "example.com", path: "/:some/1"})

				return []rule.Rule{rul}
			}(),
			tbaRules: func() []rule.Rule {
				rul := &ruleImpl{id: "2", srcID: "2"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "*", path: "/**"})

				return []rule.Rule{rul}
			}(),
			assert: func(t *testing.T, err error, _ *repository) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "conflicting rules")
			},
		},
		"overriding a rule with multiple wildcards by a more specific rule for some of the path segments defined in a different rule set is not possible": {
			initRules: func() []rule.Rule {
				rul := &ruleImpl{id: "1", srcID: "1"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "example.com", path: "/:a/:b/:c/:d"})

				return []rule.Rule{rul}
			}(),
			tbaRules: func() []rule.Rule {
				rul := &ruleImpl{id: "2", srcID: "2"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "example.com", path: "/:a/1/:c/1"})

				return []rule.Rule{rul}
			}(),
			assert: func(t *testing.T, err error, _ *repository) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "conflicting rules")
			},
		},
		"overriding of a rule defining a free wildcard at the end of the path by a more specific rule from another rule set is not possible": {
			initRules: func() []rule.Rule {
				rul := &ruleImpl{id: "1", srcID: "1"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "example.com", path: "/1/**"})

				return []rule.Rule{rul}
			}(),
			tbaRules: func() []rule.Rule {
				rul := &ruleImpl{id: "2", srcID: "2"}
				rul.routes = append(rul.routes, &routeImpl{rule: rul, host: "example.com", path: "/1/2/3"})

				return []rule.Rule{rul}
			}(),
			assert: func(t *testing.T, err error, _ *repository) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "conflicting rules")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			repo := newRepository(&ruleFactory{}).(*repository)

			err := repo.AddRuleSet(t.Context(), tc.initRules[0].SrcID(), tc.initRules)

			if len(tc.tbaRules) != 0 {
				require.NoError(t, err)

				err = repo.AddRuleSet(t.Context(), tc.tbaRules[0].SrcID(), tc.tbaRules)
			}

			tc.assert(t, err, repo)
		})
	}
}

func TestRepositoryRemoveRuleSet(t *testing.T) {
	t.Parallel()

	// GIVEN
	repo := newRepository(&ruleFactory{}).(*repository) //nolint: forcetypeassert

	rule1 := &ruleImpl{id: "1", srcID: "1"}
	rule1.routes = append(rule1.routes, &routeImpl{rule: rule1, host: "*", path: "/foo/1"})

	rule2 := &ruleImpl{id: "2", srcID: "1"}
	rule2.routes = append(rule2.routes, &routeImpl{rule: rule2, host: "*", path: "/foo/2"})

	rule3 := &ruleImpl{id: "3", srcID: "1"}
	rule3.routes = append(rule3.routes, &routeImpl{rule: rule3, host: "*", path: "/foo/4"})

	rule4 := &ruleImpl{id: "4", srcID: "1"}
	rule4.routes = append(rule4.routes, &routeImpl{rule: rule4, host: "*", path: "/foo/4"})

	rules := []rule.Rule{rule1, rule2, rule3, rule4}

	require.NoError(t, repo.AddRuleSet(t.Context(), "1", rules))
	assert.Len(t, repo.knownRules, 4)
	assert.False(t, repo.index.Empty())

	// WHEN
	err := repo.DeleteRuleSet(t.Context(), "1")

	// THEN
	require.NoError(t, err)
	assert.Empty(t, repo.knownRules)
	assert.True(t, repo.index.Empty())
}

func TestRepositoryRemoveRulesFromDifferentRuleSets(t *testing.T) {
	t.Parallel()

	// GIVEN
	repo := newRepository(&ruleFactory{}).(*repository) //nolint: forcetypeassert

	rule1 := &ruleImpl{id: "1", srcID: "bar"}
	rule1.routes = append(rule1.routes, &routeImpl{rule: rule1, host: "example.com", path: "/bar/1"})

	rule2 := &ruleImpl{id: "3", srcID: "bar"}
	rule2.routes = append(rule2.routes, &routeImpl{rule: rule2, host: "*.example.com", path: "/bar/3"})

	rule3 := &ruleImpl{id: "4", srcID: "bar"}
	rule3.routes = append(rule3.routes, &routeImpl{rule: rule3, host: "foo.com", path: "/bar/4"})

	rule4 := &ruleImpl{id: "2", srcID: "baz"}
	rule4.routes = append(rule4.routes, &routeImpl{rule: rule4, host: "bar.com", path: "/baz/2"})

	rule5 := &ruleImpl{id: "4", srcID: "foo"}
	rule5.routes = append(rule5.routes, &routeImpl{rule: rule5, host: "*", path: "/foo/4"})

	rules1 := []rule.Rule{rule1, rule2, rule3}
	rules2 := []rule.Rule{rule4}
	rules3 := []rule.Rule{rule5}

	// WHEN
	require.NoError(t, repo.AddRuleSet(t.Context(), "bar", rules1))
	require.NoError(t, repo.AddRuleSet(t.Context(), "baz", rules2))
	require.NoError(t, repo.AddRuleSet(t.Context(), "foo", rules3))

	// THEN
	assert.Len(t, repo.knownRules, 5)
	assert.False(t, repo.index.Empty())

	// WHEN
	err := repo.DeleteRuleSet(t.Context(), "bar")

	// THEN
	require.NoError(t, err)
	assert.Len(t, repo.knownRules, 2)
	assert.ElementsMatch(t, repo.knownRules, []rule.Rule{rules2[0], rules3[0]})

	_, err = repo.index.FindEntry("example.com", "/bar/1", radixtrie.LookupMatcherFunc[rule.Route](func(_ rule.Route, _, _ []string) bool { return true }))
	assert.Error(t, err) //nolint:testifylint

	_, err = repo.index.FindEntry("foo.example.com", "/bar/3", radixtrie.LookupMatcherFunc[rule.Route](func(_ rule.Route, _, _ []string) bool { return true }))
	assert.Error(t, err) //nolint:testifylint

	_, err = repo.index.FindEntry("foo.com", "/bar/4", radixtrie.LookupMatcherFunc[rule.Route](func(_ rule.Route, _, _ []string) bool { return true }))
	assert.Error(t, err) //nolint:testifylint

	_, err = repo.index.FindEntry("bar.com", "/baz/2", radixtrie.LookupMatcherFunc[rule.Route](func(_ rule.Route, _, _ []string) bool { return true }))
	assert.NoError(t, err) //nolint:testifylint

	_, err = repo.index.FindEntry("foo.bar", "/foo/4", radixtrie.LookupMatcherFunc[rule.Route](func(_ rule.Route, _, _ []string) bool { return true }))
	assert.NoError(t, err) //nolint:testifylint

	// WHEN
	err = repo.DeleteRuleSet(t.Context(), "foo")

	// THEN
	require.NoError(t, err)
	assert.Len(t, repo.knownRules, 1)
	assert.ElementsMatch(t, repo.knownRules, []rule.Rule{rules2[0]})

	_, err = repo.index.FindEntry("foo.bar", "/foo/4", radixtrie.LookupMatcherFunc[rule.Route](func(_ rule.Route, _, _ []string) bool { return true }))
	assert.Error(t, err) //nolint:testifylint

	_, err = repo.index.FindEntry("bar.com", "/baz/2", radixtrie.LookupMatcherFunc[rule.Route](func(_ rule.Route, _, _ []string) bool { return true }))
	assert.NoError(t, err) //nolint:testifylint

	// WHEN
	err = repo.DeleteRuleSet(t.Context(), "baz")

	// THEN
	require.NoError(t, err)
	assert.Empty(t, repo.knownRules)
	assert.True(t, repo.index.Empty())
}

func TestRepositoryUpdateRuleSetSingle(t *testing.T) {
	t.Parallel()

	// GIVEN
	repo := newRepository(&ruleFactory{}).(*repository) //nolint: forcetypeassert

	rule1 := &ruleImpl{id: "1", srcID: "1", hash: []byte{1}}
	rule1.routes = append(rule1.routes, &routeImpl{rule: rule1, host: "example.com", path: "/bar/1"})
	rule1.routes = append(rule1.routes, &routeImpl{rule: rule1, host: "bar.example.com", path: "/bar/1a"})

	rule2 := &ruleImpl{id: "2", srcID: "1", hash: []byte{1}}
	rule2.routes = append(rule2.routes, &routeImpl{rule: rule2, host: "example.com", path: "/bar/2"})

	rule3 := &ruleImpl{id: "3", srcID: "1", hash: []byte{1}}
	rule3.routes = append(rule3.routes, &routeImpl{rule: rule3, host: "foo.example.com", path: "/bar/2"})

	rule4 := &ruleImpl{id: "4", srcID: "1", hash: []byte{1}}
	rule4.routes = append(rule4.routes, &routeImpl{rule: rule4, host: "baz.example.com", path: "/bar/4"})

	initialRules := []rule.Rule{rule1, rule2, rule3, rule4}

	require.NoError(t, repo.AddRuleSet(t.Context(), "1", initialRules))

	// rule 1 changed: example.com/bar/1a gone, bar.example.com/bar/1b added
	rule1 = &ruleImpl{id: "1", srcID: "1", hash: []byte{2}}
	rule1.routes = append(rule1.routes, &routeImpl{rule: rule1, host: "example.com", path: "/bar/1"})
	rule1.routes = append(rule1.routes, &routeImpl{rule: rule1, host: "bar.example.com", path: "/bar/1b"})
	// rule with id 2 is deleted
	// rule 3 changed: foo.example.com/bar/2 gone, foo.example.com/foo/3 and /foo/4 added
	rule3 = &ruleImpl{id: "3", srcID: "1", hash: []byte{2}}
	rule3.routes = append(rule3.routes, &routeImpl{rule: rule3, host: "foo.example.com", path: "/foo/3"})
	rule3.routes = append(rule3.routes, &routeImpl{rule: rule3, host: "foo.example.com", path: "/foo/4"})
	// rule 4 same as before

	updatedRules := []rule.Rule{rule1, rule3, rule4}

	// WHEN
	err := repo.UpdateRuleSet(t.Context(), "1", updatedRules)

	// THEN
	require.NoError(t, err)

	assert.Len(t, repo.knownRules, 3)
	assert.False(t, repo.index.Empty())

	_, err = repo.index.FindEntry("example.com", "/bar/1",
		radixtrie.LookupMatcherFunc[rule.Route](
			func(_ rule.Route, _, _ []string) bool { return true }))
	require.NoError(t, err)
	_, err = repo.index.FindEntry("bar.example.com", "/bar/1a",
		radixtrie.LookupMatcherFunc[rule.Route](
			func(_ rule.Route, _, _ []string) bool { return true }))
	require.Error(t, err)
	_, err = repo.index.FindEntry("bar.example.com", "/bar/1b",
		radixtrie.LookupMatcherFunc[rule.Route](
			func(_ rule.Route, _, _ []string) bool { return true }))
	require.NoError(t, err)

	_, err = repo.index.FindEntry("example.com", "/bar/2",
		radixtrie.LookupMatcherFunc[rule.Route](
			func(_ rule.Route, _, _ []string) bool { return true }))
	require.Error(t, err)

	_, err = repo.index.FindEntry("foo.example.com", "/bar/2",
		radixtrie.LookupMatcherFunc[rule.Route](
			func(_ rule.Route, _, _ []string) bool { return true }))
	require.Error(t, err)
	_, err = repo.index.FindEntry("foo.example.com", "/foo/3",
		radixtrie.LookupMatcherFunc[rule.Route](
			func(_ rule.Route, _, _ []string) bool { return true }))
	require.NoError(t, err)
	_, err = repo.index.FindEntry("foo.example.com", "/foo/4",
		radixtrie.LookupMatcherFunc[rule.Route](
			func(_ rule.Route, _, _ []string) bool { return true }))
	require.NoError(t, err)

	_, err = repo.index.FindEntry("baz.example.com", "/bar/4",
		radixtrie.LookupMatcherFunc[rule.Route](
			func(_ rule.Route, _, _ []string) bool { return true }))
	require.NoError(t, err)
}

func TestRepositoryUpdateRuleSetMultiple(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		initRules    []rule.Rule
		updatedRules []rule.Rule
		assert       func(t *testing.T, err error, repo *repository)
	}{
		"successful update": {
			initRules: func() []rule.Rule {
				rule1 := &ruleImpl{id: "1", srcID: "1", hash: []byte{1}}
				rule1.routes = append(rule1.routes, &routeImpl{rule: rule1, host: "example.com", path: "/bar/1"})
				rule1.routes = append(rule1.routes, &routeImpl{rule: rule1, host: "bar.example.com", path: "/bar/1a"})

				rule2 := &ruleImpl{id: "2", srcID: "2", hash: []byte{1}}
				rule2.routes = append(rule2.routes, &routeImpl{rule: rule2, host: "example.com", path: "/bar/2"})

				return []rule.Rule{rule1, rule2}
			}(),
			updatedRules: func() []rule.Rule {
				// rule 2 changed: example.com/bar/2 gone, foo.example.com/foo/3 and /foo/4 added
				rule2 := &ruleImpl{id: "2", srcID: "2", hash: []byte{2}}
				rule2.routes = append(rule2.routes, &routeImpl{rule: rule2, host: "foo.example.com", path: "/foo/3"})
				rule2.routes = append(rule2.routes, &routeImpl{rule: rule2, host: "foo.example.com", path: "/foo/4"})

				return []rule.Rule{rule2}
			}(),
			assert: func(t *testing.T, err error, repo *repository) {
				t.Helper()

				require.NoError(t, err)

				assert.Len(t, repo.knownRules, 2)
				assert.False(t, repo.index.Empty())

				_, err = repo.index.FindEntry("example.com", "/bar/1",
					radixtrie.LookupMatcherFunc[rule.Route](
						func(_ rule.Route, _, _ []string) bool { return true }))
				require.NoError(t, err)
				_, err = repo.index.FindEntry("bar.example.com", "/bar/1a",
					radixtrie.LookupMatcherFunc[rule.Route](
						func(_ rule.Route, _, _ []string) bool { return true }))
				require.NoError(t, err)

				_, err = repo.index.FindEntry("example.com", "/bar/2",
					radixtrie.LookupMatcherFunc[rule.Route](
						func(_ rule.Route, _, _ []string) bool { return true }))
				require.Error(t, err)

				_, err = repo.index.FindEntry("foo.example.com", "/foo/3",
					radixtrie.LookupMatcherFunc[rule.Route](
						func(_ rule.Route, _, _ []string) bool { return true }))
				require.NoError(t, err)
				_, err = repo.index.FindEntry("foo.example.com", "/foo/4",
					radixtrie.LookupMatcherFunc[rule.Route](
						func(_ rule.Route, _, _ []string) bool { return true }))
				require.NoError(t, err)
			},
		},
		"rule attempts to provide a more specific host for an existing rule in a different rule set": {
			initRules: func() []rule.Rule {
				rule1 := &ruleImpl{id: "1", srcID: "1", hash: []byte{1}}
				rule1.routes = append(rule1.routes, &routeImpl{rule: rule1, host: "*.example.com", path: "/bar/1"})

				rule2 := &ruleImpl{id: "2", srcID: "2", hash: []byte{1}}
				rule2.routes = append(rule2.routes, &routeImpl{rule: rule2, host: "example.com", path: "/bar/2"})

				return []rule.Rule{rule1, rule2}
			}(),
			updatedRules: func() []rule.Rule {
				rule2 := &ruleImpl{id: "2", srcID: "2", hash: []byte{2}}
				rule2.routes = append(rule2.routes, &routeImpl{rule: rule2, host: "foo.example.com", path: "/bar/1"})

				return []rule.Rule{rule2}
			}(),
			assert: func(t *testing.T, err error, repo *repository) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "conflicting rules")

				assert.Len(t, repo.knownRules, 2)
				assert.False(t, repo.index.Empty())

				entry, err := repo.index.FindEntry("foo.example.com", "/bar/1",
					radixtrie.LookupMatcherFunc[rule.Route](
						func(_ rule.Route, _, _ []string) bool { return true }))
				require.NoError(t, err)
				assert.Equal(t, "1", entry.Value.Rule().ID())

				entry, err = repo.index.FindEntry("example.com", "/bar/2",
					radixtrie.LookupMatcherFunc[rule.Route](
						func(_ rule.Route, _, _ []string) bool { return true }))
				require.NoError(t, err)
				assert.Equal(t, "2", entry.Value.Rule().ID())
			},
		},
		"rule attempts to provide a more specific host and path for an existing rule in a different rule set": {
			initRules: func() []rule.Rule {
				rule1 := &ruleImpl{id: "1", srcID: "1", hash: []byte{1}}
				rule1.routes = append(rule1.routes, &routeImpl{rule: rule1, host: "*.example.com", path: "/:bar/1"})

				rule2 := &ruleImpl{id: "2", srcID: "2", hash: []byte{1}}
				rule2.routes = append(rule2.routes, &routeImpl{rule: rule2, host: "example.com", path: "/bar/2"})

				return []rule.Rule{rule1, rule2}
			}(),
			updatedRules: func() []rule.Rule {
				rule2 := &ruleImpl{id: "2", srcID: "2", hash: []byte{2}}
				rule2.routes = append(rule2.routes, &routeImpl{rule: rule2, host: "foo.example.com", path: "/bar/1"})

				return []rule.Rule{rule2}
			}(),
			assert: func(t *testing.T, err error, repo *repository) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "conflicting rules")

				entry, err := repo.index.FindEntry("foo.example.com", "/bar/1",
					radixtrie.LookupMatcherFunc[rule.Route](
						func(_ rule.Route, _, _ []string) bool { return true }))
				require.NoError(t, err)
				assert.Equal(t, "1", entry.Value.Rule().ID())

				entry, err = repo.index.FindEntry("example.com", "/bar/2",
					radixtrie.LookupMatcherFunc[rule.Route](
						func(_ rule.Route, _, _ []string) bool { return true }))
				require.NoError(t, err)
				assert.Equal(t, "2", entry.Value.Rule().ID())
			},
		},
		"rule attempts to provide a more generic host and path for an existing rule in a different rule set": {
			initRules: func() []rule.Rule {
				rule1 := &ruleImpl{id: "1", srcID: "1", hash: []byte{1}}
				rule1.routes = append(rule1.routes, &routeImpl{rule: rule1, host: "foo.example.com", path: "/bar/1"})

				rule2 := &ruleImpl{id: "2", srcID: "2", hash: []byte{1}}
				rule2.routes = append(rule2.routes, &routeImpl{rule: rule2, host: "example.com", path: "/bar/2"})

				return []rule.Rule{rule1, rule2}
			}(),
			updatedRules: func() []rule.Rule {
				rule2 := &ruleImpl{id: "2", srcID: "2", hash: []byte{2}}
				rule2.routes = append(rule2.routes, &routeImpl{rule: rule2, host: "*.example.com", path: "/:bar/1"})

				return []rule.Rule{rule2}
			}(),
			assert: func(t *testing.T, err error, repo *repository) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "conflicting rules")

				entry, err := repo.index.FindEntry("foo.example.com", "/bar/1",
					radixtrie.LookupMatcherFunc[rule.Route](
						func(_ rule.Route, _, _ []string) bool { return true }))
				require.NoError(t, err)
				assert.Equal(t, "1", entry.Value.Rule().ID())

				entry, err = repo.index.FindEntry("example.com", "/bar/2",
					radixtrie.LookupMatcherFunc[rule.Route](
						func(_ rule.Route, _, _ []string) bool { return true }))
				require.NoError(t, err)
				assert.Equal(t, "2", entry.Value.Rule().ID())

				_, err = repo.index.FindEntry("bar.example.com", "/foo/2",
					radixtrie.LookupMatcherFunc[rule.Route](
						func(_ rule.Route, _, _ []string) bool { return true }))
				require.Error(t, err)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			repo := newRepository(&ruleFactory{}).(*repository) //nolint: forcetypeassert

			err := repo.AddRuleSet(t.Context(), "1", tc.initRules)
			require.NoError(t, err)

			// WHEN
			err = repo.UpdateRuleSet(t.Context(), "2", tc.updatedRules)

			// THEN
			tc.assert(t, err, repo)
		})
	}

	// GIVEN
	repo := newRepository(&ruleFactory{}).(*repository) //nolint: forcetypeassert

	rule1 := &ruleImpl{id: "1", srcID: "1", hash: []byte{1}}
	rule1.routes = append(rule1.routes, &routeImpl{rule: rule1, host: "*.example.com", path: "/:1/1"})

	rule2 := &ruleImpl{id: "2", srcID: "1", hash: []byte{1}}
	rule2.routes = append(rule2.routes, &routeImpl{rule: rule2, host: "example.com", path: "/bar/2"})

	rule3 := &ruleImpl{id: "3", srcID: "1", hash: []byte{1}}
	rule3.routes = append(rule3.routes, &routeImpl{rule: rule3, host: "foo.example.com", path: "/bar/2"})

	rule4 := &ruleImpl{id: "4", srcID: "1", hash: []byte{1}}
	rule4.routes = append(rule4.routes, &routeImpl{rule: rule4, host: "baz.example.com", path: "/bar/4"})

	initialRules := []rule.Rule{rule1, rule2, rule3, rule4}

	require.NoError(t, repo.AddRuleSet(t.Context(), "1", initialRules))

	// rule 1 changed: example.com/bar/1a gone, bar.example.com/bar/1b added
	rule1 = &ruleImpl{id: "1", srcID: "1", hash: []byte{2}}
	rule1.routes = append(rule1.routes, &routeImpl{rule: rule1, host: "example.com", path: "/bar/1"})
	rule1.routes = append(rule1.routes, &routeImpl{rule: rule1, host: "bar.example.com", path: "/bar/1b"})
	// rule with id 2 is deleted
	// rule 3 changed: foo.example.com/bar/2 gone, foo.example.com/foo/3 and /foo/4 added
	rule3 = &ruleImpl{id: "3", srcID: "1", hash: []byte{2}}
	rule3.routes = append(rule3.routes, &routeImpl{rule: rule3, host: "foo.example.com", path: "/foo/3"})
	rule3.routes = append(rule3.routes, &routeImpl{rule: rule3, host: "foo.example.com", path: "/foo/4"})
	// rule 4 same as before

	updatedRules := []rule.Rule{rule1, rule3, rule4}

	// WHEN
	err := repo.UpdateRuleSet(t.Context(), "1", updatedRules)

	// THEN
	require.NoError(t, err)

	assert.Len(t, repo.knownRules, 3)
	assert.False(t, repo.index.Empty())

	_, err = repo.index.FindEntry("example.com", "/bar/1",
		radixtrie.LookupMatcherFunc[rule.Route](
			func(_ rule.Route, _, _ []string) bool { return true }))
	require.NoError(t, err)
	_, err = repo.index.FindEntry("bar.example.com", "/bar/1a",
		radixtrie.LookupMatcherFunc[rule.Route](
			func(_ rule.Route, _, _ []string) bool { return true }))
	require.Error(t, err)
	_, err = repo.index.FindEntry("bar.example.com", "/bar/1b",
		radixtrie.LookupMatcherFunc[rule.Route](
			func(_ rule.Route, _, _ []string) bool { return true }))
	require.NoError(t, err)

	_, err = repo.index.FindEntry("example.com", "/bar/2",
		radixtrie.LookupMatcherFunc[rule.Route](
			func(_ rule.Route, _, _ []string) bool { return true }))
	require.Error(t, err)

	_, err = repo.index.FindEntry("foo.example.com", "/bar/2",
		radixtrie.LookupMatcherFunc[rule.Route](
			func(_ rule.Route, _, _ []string) bool { return true }))
	require.Error(t, err)
	_, err = repo.index.FindEntry("foo.example.com", "/foo/3",
		radixtrie.LookupMatcherFunc[rule.Route](
			func(_ rule.Route, _, _ []string) bool { return true }))
	require.NoError(t, err)
	_, err = repo.index.FindEntry("foo.example.com", "/foo/4",
		radixtrie.LookupMatcherFunc[rule.Route](
			func(_ rule.Route, _, _ []string) bool { return true }))
	require.NoError(t, err)

	_, err = repo.index.FindEntry("baz.example.com", "/bar/4",
		radixtrie.LookupMatcherFunc[rule.Route](
			func(_ rule.Route, _, _ []string) bool { return true }))
	require.NoError(t, err)
}

func TestRepositoryFindRule(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		requestURL       *url.URL
		addRules         func(t *testing.T, repo *repository)
		configureFactory func(t *testing.T, factory *mocks.FactoryMock)
		assert           func(t *testing.T, err error, rul rule.Rule)
	}{
		"no matching rule": {
			requestURL: &url.URL{Scheme: "http", Host: "foo.bar", Path: "/baz"},
			configureFactory: func(t *testing.T, factory *mocks.FactoryMock) {
				t.Helper()

				factory.EXPECT().HasDefaultRule().Return(false)
			},
			assert: func(t *testing.T, err error, _ rule.Rule) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrNoRuleFound)
			},
		},
		"matches default rule": {
			requestURL: &url.URL{Scheme: "http", Host: "foo.bar", Path: "/baz"},
			configureFactory: func(t *testing.T, factory *mocks.FactoryMock) {
				t.Helper()

				factory.EXPECT().HasDefaultRule().Return(true)
				factory.EXPECT().DefaultRule().Return(&ruleImpl{id: "test", isDefault: true})
			},
			assert: func(t *testing.T, err error, rul rule.Rule) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, &ruleImpl{id: "test", isDefault: true}, rul)
			},
		},
		"simple upstream rule match": {
			requestURL: &url.URL{Scheme: "http", Host: "foo.bar", Path: "/baz/bar"},
			configureFactory: func(t *testing.T, factory *mocks.FactoryMock) {
				t.Helper()

				factory.EXPECT().HasDefaultRule().Return(false)
			},
			addRules: func(t *testing.T, repo *repository) {
				t.Helper()

				rule1 := &ruleImpl{id: "test", srcID: "1", hash: []byte{1}}
				rule1.routes = append(rule1.routes, &routeImpl{rule: rule1, host: "*", path: "/baz/bar", matcher: andMatcher{}})

				err := repo.AddRuleSet(t.Context(), "1", []rule.Rule{rule1})
				require.NoError(t, err)
			},
			assert: func(t *testing.T, err error, rul rule.Rule) {
				t.Helper()

				require.NoError(t, err)

				impl, ok := rul.(*ruleImpl)
				require.True(t, ok)

				require.Equal(t, "test", impl.id)
				require.Equal(t, "1", impl.srcID)
			},
		},
		"upstream rule match with backtracking due to constraints limitations within the rule set": {
			requestURL: &url.URL{Scheme: "http", Host: "foo.bar", Path: "/baz/bar"},
			configureFactory: func(t *testing.T, factory *mocks.FactoryMock) {
				t.Helper()

				factory.EXPECT().HasDefaultRule().Return(false)
			},
			addRules: func(t *testing.T, repo *repository) {
				t.Helper()

				rule1 := &ruleImpl{id: "rule1", srcID: "1", hash: []byte{1}}
				rule1.routes = append(rule1.routes,
					&routeImpl{
						rule: rule1,
						host: "foo.bar",
						path: "/baz/:id",
						matcher: &pathParamMatcher{
							newExactMatcher("foo"),
							"id",
							config.EncodedSlashesOff,
						},
					},
				)

				rule2 := &ruleImpl{id: "rule2", srcID: "1", hash: []byte{1}}
				rule2.routes = append(rule2.routes,
					&routeImpl{
						rule: rule2,
						host: "foo.bar",
						path: "/baz/:id",
						matcher: &pathParamMatcher{
							newExactMatcher("baz"),
							"id",
							config.EncodedSlashesOff,
						},
					},
				)

				rule3 := &ruleImpl{id: "rule3", srcID: "1", hash: []byte{1}}
				rule3.routes = append(rule3.routes,
					&routeImpl{
						rule:    rule3,
						host:    "*.bar",
						path:    "/baz/**",
						matcher: andMatcher{},
					},
				)

				err := repo.AddRuleSet(t.Context(), "1", []rule.Rule{rule1, rule2, rule3})
				require.NoError(t, err)
			},
			assert: func(t *testing.T, err error, rul rule.Rule) {
				t.Helper()

				require.NoError(t, err)

				impl, ok := rul.(*ruleImpl)
				require.True(t, ok)

				require.Equal(t, "rule3", impl.id)
				require.Equal(t, "1", impl.srcID)
			},
		},
		"upstream rule match with backtracking within the rule set": {
			requestURL: &url.URL{Scheme: "http", Host: "foo.bar", Path: "/baz/foo/bar/baz"},
			configureFactory: func(t *testing.T, factory *mocks.FactoryMock) {
				t.Helper()

				factory.EXPECT().HasDefaultRule().Return(false)
			},
			addRules: func(t *testing.T, repo *repository) {
				t.Helper()

				rule1 := &ruleImpl{id: "rule1", srcID: "1", hash: []byte{1}}
				rule1.routes = append(rule1.routes,
					&routeImpl{
						rule:    rule1,
						host:    "foo.bar",
						path:    "/baz/foo/:id",
						matcher: &andMatcher{},
					},
				)

				rule2 := &ruleImpl{id: "rule2", srcID: "1", hash: []byte{1}}
				rule2.routes = append(rule2.routes,
					&routeImpl{
						rule:    rule2,
						host:    "foo.bar",
						path:    "/baz/**",
						matcher: andMatcher{},
					},
				)

				err := repo.AddRuleSet(t.Context(), "1", []rule.Rule{rule1, rule2})
				require.NoError(t, err)
			},
			assert: func(t *testing.T, err error, rul rule.Rule) {
				t.Helper()

				require.NoError(t, err)

				impl, ok := rul.(*ruleImpl)
				require.True(t, ok)

				require.Equal(t, "rule2", impl.id)
				require.Equal(t, "1", impl.srcID)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			addRules := x.IfThenElse(tc.addRules != nil,
				tc.addRules,
				func(t *testing.T, _ *repository) { t.Helper() })

			factory := mocks.NewFactoryMock(t)
			tc.configureFactory(t, factory)

			repo := newRepository(factory).(*repository) //nolint: forcetypeassert

			addRules(t, repo)

			req := &heimdall.Request{Method: http.MethodGet, URL: &heimdall.URL{URL: *tc.requestURL}}
			ctx := mocks2.NewRequestContextMock(t)
			ctx.EXPECT().Context().Maybe().Return(t.Context())
			ctx.EXPECT().Request().Return(req)

			// WHEN
			rul, err := repo.FindRule(ctx)

			// THEN
			tc.assert(t, err, rul)
		})
	}
}
