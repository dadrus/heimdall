// Copyright 2023 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
package cellib

import (
	"fmt"
	"sync"
	"testing"

	"cel.dev/cel-go/cel"
	"github.com/stretchr/testify/require"
)

func TestNetworks(t *testing.T) {
	t.Parallel()

	env, err := cel.NewEnv(
		Networks(),
	)
	require.NoError(t, err)

	for _, tc := range []string{
		`"192.168.1.10" in networks("192.168.1.0/24")`,
		`["192.168.1.10"].all(ip, ip in networks("192.168.1.0/24"))`,
		`!["10.0.1.1"].exists(ip, ip in networks("192.168.1.0/24"))`,
		`["192.168.1.10", "192.168.1.12"] in networks(["192.168.1.0/24"])`,
		`["192.168.1.10", "10.0.1.1"].all(ip, ip in networks(["192.168.1.0/24", "10.0.0.0/16"]))`,
		`["192.168.1.10", "10.0.1.1"].exists(ip, ip in networks(["10.0.0.0/16"]))`,
	} {
		t.Run(tc, func(t *testing.T) {
			ast, iss := env.Compile(tc)
			if iss != nil {
				require.NoError(t, iss.Err())
			}

			ast, iss = env.Check(ast)
			if iss != nil {
				require.NoError(t, iss.Err())
			}

			prg, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
			require.NoError(t, err)

			out, _, err := prg.Eval(map[string]any{})
			require.NoError(t, err)
			require.Equal(t, true, out.Value()) //nolint:testifylint
		})
	}
}

func TestNetworksConcurrentEvaluation(t *testing.T) {
	env, err := cel.NewEnv(Library())
	require.NoError(t, err)

	expr, err := CompileExpression(env, `"10.1.2.3" in networks("10.0.0.0/8")`, "denied")
	require.NoError(t, err)

	const (
		goroutines  = 32
		evaluations = 200
	)

	var wg sync.WaitGroup

	start := make(chan struct{})
	errs := make(chan error, goroutines)

	for range goroutines {
		wg.Go(func() {
			<-start

			for range evaluations {
				if err := expr.Eval(map[string]any{}); err != nil {
					errs <- err

					return
				}
			}
		})
	}

	close(start)
	wg.Wait()
	close(errs)

	for err := range errs {
		require.NoError(t, err)
	}
}

func TestNetworksConcurrentEvaluationWithDynamicCIDRs(t *testing.T) {
	env, err := cel.NewEnv(
		Library(),
		cel.Variable("cidrs", cel.ListType(cel.StringType)),
	)
	require.NoError(t, err)

	expr, err := CompileExpression(env, `"10.1.2.3" in networks(cidrs)`, "denied")
	require.NoError(t, err)

	const (
		goroutines  = 32
		evaluations = 200
	)

	var wg sync.WaitGroup

	start := make(chan struct{})
	errs := make(chan error, goroutines)

	for idx := range goroutines {
		wg.Go(func() {
			dynamicCIDR := fmt.Sprintf("192.168.%d.0/24", idx)
			cidrs := []string{dynamicCIDR, "10.0.0.0/8"}
			activation := map[string]any{"cidrs": cidrs}

			<-start

			for range evaluations {
				if err := expr.Eval(activation); err != nil {
					errs <- err

					return
				}
			}

			if cidrs[0] != dynamicCIDR || cidrs[1] != "10.0.0.0/8" {
				errs <- fmt.Errorf("networks modified input CIDRs: %v", cidrs)
			}
		})
	}

	close(start)
	wg.Wait()
	close(errs)

	for err := range errs {
		require.NoError(t, err)
	}
}

func TestNetworkCacheConcurrentReuse(t *testing.T) {
	t.Parallel()

	var cache networkCache

	const goroutines = 32

	var wg sync.WaitGroup

	start := make(chan struct{})
	results := make(chan IPNetworks, goroutines)
	errs := make(chan error, goroutines)

	for range goroutines {
		wg.Go(func() {
			<-start

			networks, err := cache.getOrCreate([]string{"10.0.0.0/8"})
			if err != nil {
				errs <- err

				return
			}

			results <- networks
		})
	}

	close(start)
	wg.Wait()
	close(results)
	close(errs)

	for err := range errs {
		require.NoError(t, err)
	}

	var ranger any

	for networks := range results {
		if ranger == nil {
			ranger = networks.ranger

			continue
		}

		require.Same(t, ranger, networks.ranger)
	}

	snapshot := cache.snapshot.Load()
	require.NotNil(t, snapshot)
	require.Len(t, snapshot.entries, 1)
	require.Equal(t, []string{"10.0.0.0/8"}, snapshot.entries[0].cidrs)
	require.Same(t, ranger, snapshot.entries[0].networks.ranger)
}

func TestNetworkCacheOwnsCIDRs(t *testing.T) {
	t.Parallel()

	var cache networkCache

	cidrs := []string{"192.168.0.0/16", "10.0.0.0/8"}
	original := []string{"192.168.0.0/16", "10.0.0.0/8"}

	networks, err := cache.getOrCreate(cidrs)
	require.NoError(t, err)
	require.Equal(t, original, cidrs)

	cidrs[0] = "172.16.0.0/12"

	cached, found := cache.get(original)
	require.True(t, found)
	require.Same(t, networks.ranger, cached.ranger)

	_, found = cache.get(cidrs)
	require.False(t, found)

	snapshot := cache.snapshot.Load()
	require.NotNil(t, snapshot)
	require.Len(t, snapshot.entries, 1)
	require.Equal(t, original, snapshot.entries[0].cidrs)
}

func TestNetworkCacheReusesCIDRsRegardlessOfOrder(t *testing.T) {
	t.Parallel()

	var cache networkCache

	first, err := cache.getOrCreate([]string{
		"192.168.0.0/16",
		"10.0.0.0/8",
	})
	require.NoError(t, err)

	second, err := cache.getOrCreate([]string{
		"10.0.0.0/8",
		"192.168.0.0/16",
	})
	require.NoError(t, err)

	require.Same(t, first.ranger, second.ranger)

	snapshot := cache.snapshot.Load()
	require.NotNil(t, snapshot)
	require.Len(t, snapshot.entries, 1)
}

func TestSameCIDRs(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		left     []string
		right    []string
		expected bool
	}{
		"same order": {
			left:     []string{"10.0.0.0/8", "192.168.0.0/16"},
			right:    []string{"10.0.0.0/8", "192.168.0.0/16"},
			expected: true,
		},
		"different order": {
			left:     []string{"10.0.0.0/8", "192.168.0.0/16"},
			right:    []string{"192.168.0.0/16", "10.0.0.0/8"},
			expected: true,
		},
		"same duplicates": {
			left:     []string{"10.0.0.0/8", "10.0.0.0/8", "192.168.0.0/16"},
			right:    []string{"192.168.0.0/16", "10.0.0.0/8", "10.0.0.0/8"},
			expected: true,
		},
		"different duplicates": {
			left:     []string{"10.0.0.0/8", "10.0.0.0/8", "192.168.0.0/16"},
			right:    []string{"10.0.0.0/8", "192.168.0.0/16", "192.168.0.0/16"},
			expected: false,
		},
		"different values": {
			left:     []string{"10.0.0.0/8", "192.168.0.0/16"},
			right:    []string{"10.0.0.0/8", "172.16.0.0/12"},
			expected: false,
		},
		"different lengths": {
			left:     []string{"10.0.0.0/8"},
			right:    []string{"10.0.0.0/8", "192.168.0.0/16"},
			expected: false,
		},
		"empty": {
			left:     nil,
			right:    []string{},
			expected: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, tc.expected, sameCIDRs(tc.left, tc.right))
		})
	}
}
