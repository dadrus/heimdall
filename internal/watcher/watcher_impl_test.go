// Copyright 2024 Dimitrij Drus <dadrus@gmx.de>
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

package watcher

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestWatcherLifeCycle(t *testing.T) {
	t.Parallel()

	// GIVEN
	cw, err := newWatcher(log.Logger)
	require.NoError(t, err)

	cw.start(t.Context())
	defer cw.stop(t.Context())

	testDir := t.TempDir()
	f1, err := os.Create(filepath.Join(testDir, "file1"))
	require.NoError(t, err)

	f2, err := os.Create(filepath.Join(testDir, "file2"))
	require.NoError(t, err)

	f3, err := os.Create(filepath.Join(testDir, "file3"))
	require.NoError(t, err)

	cl1 := NewChangeListenerMock(t)
	cl2 := NewChangeListenerMock(t)
	cl3 := NewChangeListenerMock(t)
	cl4 := NewChangeListenerMock(t)

	cl1.EXPECT().OnChanged(mock.Anything).Times(2)
	cl2.EXPECT().OnChanged(mock.Anything).Once()
	cl3.EXPECT().OnChanged(mock.Anything).Once()

	err = cw.Add(f1.Name(), cl1)
	require.NoError(t, err)
	err = cw.Add(f2.Name(), cl2)
	require.NoError(t, err)
	err = cw.Add(f2.Name(), cl3)
	require.NoError(t, err)
	err = cw.Add(f3.Name(), cl4)
	require.NoError(t, err)

	// WHEN
	f1.WriteString("foo")
	time.Sleep(100 * time.Millisecond)

	f1.WriteString("bar")
	time.Sleep(100 * time.Millisecond)

	f2.WriteString("baz")
	time.Sleep(100 * time.Millisecond)
}
