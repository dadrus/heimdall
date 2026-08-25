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
	"net"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/operators"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"
	"github.com/yl2chen/cidranger"
)

//nolint:gochecknoglobals
var ipNetworksType = cel.ObjectType(reflect.TypeOf(IPNetworks{}).String(), traits.ReceiverType|traits.ContainerType)

func newIPNetworks(cidrs []string) (IPNetworks, error) {
	ranger := cidranger.NewPCTrieRanger()

	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return IPNetworks{}, err
		}

		if err = ranger.Insert(cidranger.NewBasicRangerEntry(*ipNet)); err != nil {
			return IPNetworks{}, err
		}
	}

	return IPNetworks{ranger: ranger}, nil
}

type IPNetworks struct {
	ranger cidranger.Ranger
}

func (n IPNetworks) ConvertToNative(typeDesc reflect.Type) (any, error) {
	rangerType := reflect.TypeOf(n.ranger)
	if rangerType != nil && rangerType.AssignableTo(typeDesc) {
		return n.ranger, nil
	}

	if reflect.TypeOf(n).AssignableTo(typeDesc) {
		return n, nil
	}

	return nil, fmt.Errorf("%w: from 'networks' to '%v'", errTypeConversion, typeDesc)
}

func (n IPNetworks) ConvertToType(typeVal ref.Type) ref.Val {
	switch typeVal {
	case ipNetworksType:
		return n
	case cel.TypeType:
		return ipNetworksType
	}

	return types.NewErr("type conversion error from 'networks' to '%s'", typeVal)
}

func (n IPNetworks) Equal(other ref.Val) ref.Val {
	otherNetworks, ok := other.(IPNetworks)

	return types.Bool(ok && n.ranger == otherNetworks.ranger)
}

func (n IPNetworks) Type() ref.Type { return ipNetworksType }

func (n IPNetworks) Value() any { return n.ranger }

func (n IPNetworks) Contains(value ref.Val) ref.Val {
	if singleIP, ok := value.Value().(string); ok {
		return types.Bool(n.containsIP(singleIP))
	}

	if lister, ok := value.(traits.Lister); ok {
		ips, err := lister.ConvertToNative(reflect.TypeOf([]string{}))
		if err != nil {
			return types.WrapErr(err)
		}

		return types.Bool(n.containsAll(ips.([]string))) // nolint: forcetypeassert
	}

	return types.False
}

func (n IPNetworks) containsIP(ip string) bool {
	res, _ := n.ranger.Contains(net.ParseIP(ip))

	return res
}

func (n IPNetworks) containsAll(ips []string) bool {
	for _, ip := range ips {
		if !n.containsIP(ip) {
			return false
		}
	}

	return true
}

type networkCache struct {
	mu       sync.Mutex
	snapshot atomic.Pointer[networkCacheSnapshot]
}

type networkCacheSnapshot struct {
	entries []networkCacheEntry
}

type networkCacheEntry struct {
	cidrs    []string
	networks IPNetworks
}

func (c *networkCache) getOrCreate(cidrs []string) (IPNetworks, error) {
	if networks, found := c.get(cidrs); found {
		return networks, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Another evaluation might have populated the cache while waiting for the lock.
	if networks, found := c.get(cidrs); found {
		return networks, nil
	}

	// Cache entries are immutable once published and therefore must own their CIDR slice.
	cidrs = slices.Clone(cidrs)

	networks, err := newIPNetworks(cidrs)
	if err != nil {
		return IPNetworks{}, err
	}

	current := c.snapshot.Load()
	var entries []networkCacheEntry
	if current != nil {
		entries = current.entries
	}

	next := make([]networkCacheEntry, len(entries)+1)
	copy(next, entries)
	next[len(entries)] = networkCacheEntry{
		cidrs:    cidrs,
		networks: networks,
	}

	c.snapshot.Store(&networkCacheSnapshot{entries: next})

	return networks, nil
}

func (c *networkCache) get(cidrs []string) (IPNetworks, bool) {
	snapshot := c.snapshot.Load()
	if snapshot == nil {
		return IPNetworks{}, false
	}

	for _, entry := range snapshot.entries {
		if sameCIDRs(entry.cidrs, cidrs) {
			return entry.networks, true
		}
	}

	return IPNetworks{}, false
}

// sameCIDRs compares two CIDR lists as multisets. This preserves the previous
// cache semantics, where CIDRs were sorted before comparison, without sorting
// or allocating on the cache-hit path.
func sameCIDRs(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}

	if slices.Equal(left, right) {
		return true
	}

	for idx, cidr := range left {
		if slices.Contains(left[:idx], cidr) {
			continue
		}

		leftCount := 0
		rightCount := 0

		for _, candidate := range left {
			if candidate == cidr {
				leftCount++
			}
		}

		for _, candidate := range right {
			if candidate == cidr {
				rightCount++
			}
		}

		if leftCount != rightCount {
			return false
		}
	}

	return true
}

func Networks() cel.EnvOption {
	return cel.Lib(networksLib{})
}

type networksLib struct{}

func (networksLib) LibraryName() string {
	return "dadrus.heimdall.networks"
}

func (networksLib) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

func (networksLib) CompileOptions() []cel.EnvOption {
	cache := networkCache{}

	return []cel.EnvOption{
		// IPNetworks specific functions
		cel.Function("networks",
			cel.Overload("networks_from_cidr",
				[]*cel.Type{cel.StringType}, ipNetworksType,
				cel.UnaryBinding(func(netVal ref.Val) ref.Val {
					addresses := []string{netVal.Value().(string)} // nolint: forcetypeassert

					networks, err := cache.getOrCreate(addresses)
					if err != nil {
						return types.WrapErr(err)
					}

					return networks
				}),
			),
			cel.Overload("networks_from_cidr_array",
				[]*cel.Type{cel.ListType(cel.StringType)}, ipNetworksType,
				cel.UnaryBinding(func(netsVal ref.Val) ref.Val {
					cidrs, err := netsVal.ConvertToNative(reflect.TypeOf([]string{}))
					if err != nil {
						return types.WrapErr(err)
					}

					networks, err := cache.getOrCreate(cidrs.([]string)) // nolint: forcetypeassert
					if err != nil {
						return types.WrapErr(err)
					}

					return networks
				}),
			),
		),
		cel.Function(operators.In,
			cel.Overload("ip_in_networks",
				[]*cel.Type{cel.StringType, ipNetworksType}, types.BoolType),
			cel.Overload("ips_in_networks",
				[]*cel.Type{cel.ListType(cel.StringType), ipNetworksType}, types.BoolType),
		),
	}
}
