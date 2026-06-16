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

package httpx

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIPsFromXForwardedFor(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		dst     []string
		values  []string
		want    []string
		wantErr bool
	}{
		"empty values": {
			values: nil,
			want:   nil,
		},
		"single IPv4": {
			values: []string{"192.0.2.1"},
			want:   []string{"192.0.2.1"},
		},
		"single IPv6": {
			values: []string{"2001:db8::1"},
			want:   []string{"2001:db8::1"},
		},
		"does not canonicalize IPs": {
			values: []string{"2001:0db8:0000:0000:0000:0000:0000:0001"},
			want:   []string{"2001:0db8:0000:0000:0000:0000:0000:0001"},
		},
		"comma separated values": {
			values: []string{"192.0.2.1, 198.51.100.2"},
			want:   []string{"192.0.2.1", "198.51.100.2"},
		},
		"multiple header values": {
			values: []string{"192.0.2.1", "198.51.100.2"},
			want:   []string{"192.0.2.1", "198.51.100.2"},
		},
		"trims whitespace": {
			values: []string{" 192.0.2.1 ,\t198.51.100.2 "},
			want:   []string{"192.0.2.1", "198.51.100.2"},
		},
		"ignores empty elements": {
			values: []string{" , 192.0.2.1, ,198.51.100.2, "},
			want:   []string{"192.0.2.1", "198.51.100.2"},
		},
		"appends to existing slice": {
			dst:    []string{"10.0.0.1"},
			values: []string{"192.0.2.1"},
			want:   []string{"10.0.0.1", "192.0.2.1"},
		},
		"rejects invalid IP": {
			values:  []string{"192.0.2.1, invalid"},
			want:    []string{"192.0.2.1"},
			wantErr: true,
		},
		"rejects unknown": {
			values:  []string{"unknown"},
			wantErr: true,
		},
		"rejects obfuscated identifier": {
			values:  []string{"_hidden"},
			wantErr: true,
		},
		"rejects IPv4 with port": {
			values:  []string{"192.0.2.1:1234"},
			wantErr: true,
		},
		"rejects bracketed IPv6": {
			values:  []string{"[2001:db8::1]"},
			wantErr: true,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			got, err := IPsFromXForwardedFor(tc.dst, tc.values)

			if tc.wantErr {
				require.Error(t, err)
				require.ErrorIs(t, err, ErrInvalidForwardedIP)
			} else {
				require.NoError(t, err)
			}

			assert.Equal(t, tc.want, got)
		})
	}
}

func TestIPsFromForwarded(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		dst     []string
		values  []string
		want    []string
		wantErr bool
	}{
		"empty values": {
			values: nil,
			want:   nil,
		},
		"single IPv4 for parameter": {
			values: []string{"for=192.0.2.1"},
			want:   []string{"192.0.2.1"},
		},
		"single IPv6 for parameter quoted and bracketed": {
			values: []string{`for="[2001:db8::1]"`},
			want:   []string{"2001:db8::1"},
		},
		"does not canonicalizes IPv6": {
			values: []string{`for="[2001:0db8:0000:0000:0000:0000:0000:0001]"`},
			want:   []string{"2001:0db8:0000:0000:0000:0000:0000:0001"},
		},
		"quoted IPv4": {
			values: []string{`for="192.0.2.1"`},
			want:   []string{"192.0.2.1"},
		},
		"case insensitive for parameter": {
			values: []string{"For=192.0.2.1"},
			want:   []string{"192.0.2.1"},
		},
		"ignores non-for parameters": {
			values: []string{"proto=https;host=example.com;for=192.0.2.1"},
			want:   []string{"192.0.2.1"},
		},
		"multiple forwarded entries": {
			values: []string{"for=192.0.2.1;proto=https, for=198.51.100.2;proto=http"},
			want:   []string{"192.0.2.1", "198.51.100.2"},
		},
		"multiple header values": {
			values: []string{"for=192.0.2.1", "for=198.51.100.2"},
			want:   []string{"192.0.2.1", "198.51.100.2"},
		},
		"does not split comma inside quoted string": {
			values: []string{`for=192.0.2.1;host="a,b.example", for=198.51.100.2`},
			want:   []string{"192.0.2.1", "198.51.100.2"},
		},
		"does not split semicolon inside quoted string": {
			values: []string{`for=192.0.2.1;host="a;b.example";proto=https, for=198.51.100.2`},
			want:   []string{"192.0.2.1", "198.51.100.2"},
		},
		"appends to existing slice": {
			dst:    []string{"10.0.0.1"},
			values: []string{"for=192.0.2.1"},
			want:   []string{"10.0.0.1", "192.0.2.1"},
		},
		"ignores unknown node": {
			values: []string{"for=unknown, for=192.0.2.1"},
			want:   []string{"192.0.2.1"},
		},
		"ignores quoted unknown node": {
			values: []string{`for="unknown", for=192.0.2.1`},
			want:   []string{"192.0.2.1"},
		},
		"ignores obfuscated node": {
			values: []string{"for=_hidden, for=192.0.2.1"},
			want:   []string{"192.0.2.1"},
		},
		"forwarded quoted IPv4 with escaped digit": {
			values: []string{`for="192.0.2.\1"`},
			want:   []string{"192.0.2.1"},
		},
		"forwarded quoted IPv4 with escaped quote": {
			values:  []string{`for="192.0.2.1\""`},
			wantErr: true,
		},
		"forwarded with escaped quoted separator in non-for parameter": {
			values: []string{`host="a\,b.example";for=192.0.2.1`},
			want:   []string{"192.0.2.1"},
		},
		"forwarded with unterminated quote in non-for parameter": {
			values:  []string{`host="example.com;for=192.0.2.1`},
			wantErr: true,
		},
		"rejects invalid IP": {
			values:  []string{"for=invalid"},
			wantErr: true,
		},
		"rejects empty for value": {
			values:  []string{"for="},
			wantErr: true,
		},
		"rejects quoted empty for value": {
			values:  []string{`for=""`},
			wantErr: true,
		},
		"rejects unclosed quote": {
			values:  []string{`for="192.0.2.1`},
			wantErr: true,
		},
		"rejects dangling quoted escape 1": {
			values:  []string{`for="192.0.2.1\`},
			wantErr: true,
		},
		"rejects dangling quoted escape 2": {
			values:  []string{`for="192.0.2.1\"`},
			wantErr: true,
		},
		"rejects IPv4 with port": {
			values:  []string{"for=192.0.2.1:1234"},
			wantErr: true,
		},
		"rejects bracketed IPv6 with port": {
			values:  []string{`for="[2001:db8::1]:443"`},
			wantErr: true,
		},
		"rejects unquoted bracketed IPv6": {
			values:  []string{"for=[2001:db8::1]"},
			wantErr: true,
		},
		"rejects malformed bracketed IPv6": {
			values:  []string{`for="[2001:db8::1"`},
			wantErr: true,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			got, err := IPsFromForwarded(tc.dst, tc.values)

			if tc.wantErr {
				require.Error(t, err)
				require.ErrorIs(t, err, ErrInvalidForwardedIP)
			} else {
				require.NoError(t, err)
			}

			assert.Equal(t, tc.want, got)
		})
	}
}
