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
	"net"

	"github.com/yl2chen/cidranger"
)

func NewCIDRMatcher(cidrs []string) (*CIDRMatcher, error) {
	ranger := cidranger.NewPCTrieRanger()

	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}

		if err := ranger.Insert(cidranger.NewBasicRangerEntry(*ipNet)); err != nil {
			return nil, err
		}
	}

	return &CIDRMatcher{r: ranger}, nil
}

type CIDRMatcher struct {
	r cidranger.Ranger
}

func (c *CIDRMatcher) Match(ips ...string) bool {
	for _, ip := range ips {
		ok, _ := c.r.Contains(net.ParseIP(ip))
		if ok {
			return true
		}
	}

	return false
}
