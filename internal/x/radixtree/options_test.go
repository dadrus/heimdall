// Copyright 2022-2025 Dimitrij Drus <dadrus@gmx.de>
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

package radixtree

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValuesConstrainedTree(t *testing.T) {
	t.Parallel()

	// GIVEN
	tree1 := New[string](WithValuesConstraints[string](func(oldValues []string, _ string) bool {
		return len(oldValues) == 0
	}))

	tree2 := New[string]()

	err := tree1.Add("/foo", "bar")
	require.NoError(t, err)

	err = tree2.Add("/foo", "bar")
	require.NoError(t, err)

	// WHEN
	err1 := tree1.Add("/foo", "bar")
	err2 := tree2.Add("/foo", "bar")

	// THEN
	require.Error(t, err1)
	require.NoError(t, err2)
}
