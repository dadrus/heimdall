// Copyright 2023 Dimitrij Drus <dadrus@gmx.de>
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

package httpx

import (
	"net"
	"strconv"
)

func IPFromHostPort(hp string) string {
	host, _, err := net.SplitHostPort(hp)
	if err != nil {
		return ""
	}

	if len(host) > 0 && host[0] == '[' {
		return host[1 : len(host)-1]
	}

	return host
}

func HostPort(hp string) (string, int) {
	host, pStr, err := net.SplitHostPort(hp)
	if err != nil {
		return "", -1
	}

	p, err := strconv.ParseUint(pStr, 10, 16)
	if err != nil {
		return host, -1
	}

	return host, int(p)
}
