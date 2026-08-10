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

package trustedproxy

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRemoveForwardingHeaders(t *testing.T) {
	t.Parallel()

	// GIVEN
	headers := http.Header{
		"Forwarded":          []string{"for=172.17.1.2;proto=https"},
		"X-Forwarded-For":    []string{"172.17.1.2"},
		"X-Forwarded-Proto":  []string{"https"},
		"X-Forwarded-Host":   []string{"foobar.com"},
		"X-Forwarded-Uri":    []string{"/test?foo=bar"},
		"X-Forwarded-Path":   []string{"/test"},
		"X-Forwarded-Method": []string{"GET"},
		"X-Foo-Bar":          []string{"foo"},
	}

	// WHEN
	RemoveForwardingHeaders(headers.Del)

	// THEN
	require.Equal(t, http.Header{
		"X-Foo-Bar": []string{"foo"},
	}, headers)
}
