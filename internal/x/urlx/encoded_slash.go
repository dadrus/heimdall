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

package urlx

import "strings"

// ContainsEncodedSlash reports whether path contains a URL-encoded slash
// sequence, case-insensitive, e.g. %2F or %2f.
func ContainsEncodedSlash(path string) bool {
	for i := strings.IndexByte(path, '%'); i != -1; {
		if i+2 < len(path) && path[i+1] == '2' && (path[i+2]|0x20) == 'f' { //nolint:mnd
			return true
		}

		next := strings.IndexByte(path[i+1:], '%')
		if next == -1 {
			break
		}

		i += next + 1
	}

	return false
}
