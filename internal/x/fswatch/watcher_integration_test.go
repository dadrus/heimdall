// Copyright 2026 Dimitrij Drus
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package fswatch

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestWatcherIntegrationObservesFileChange(t *testing.T) {
	t.Parallel()

	events := make(chan Event, 16)
	dir := t.TempDir()
	path := filepath.Join(dir, "key_and_cert.pem")

	require.NoError(t, os.WriteFile(path, []byte("initial"), 0o600))

	watcher, err := New(EventHandlerFunc(func(evt Event) error {
		events <- evt

		return nil
	}), WithLogger(zerolog.Nop()))
	require.NoError(t, err)

	require.NoError(t, watcher.Add(path))
	require.NoError(t, watcher.Start(context.Background()))

	t.Cleanup(func() {
		require.NoError(t, watcher.Stop(context.Background()))
	})

	require.NoError(t, os.WriteFile(path, []byte("updated"), 0o600))

	requireEventuallyReceives(t, events, Event{
		Path: filepath.Clean(path),
		Op:   OpChanged,
	})
}

func TestWatcherIntegrationObservesFileDeletion(t *testing.T) {
	t.Parallel()

	events := make(chan Event, 16)
	dir := t.TempDir()
	path := filepath.Join(dir, "key_and_cert.pem")

	require.NoError(t, os.WriteFile(path, []byte("initial"), 0o600))

	watcher, err := New(EventHandlerFunc(func(evt Event) error {
		events <- evt

		return nil
	}), WithLogger(zerolog.Nop()))
	require.NoError(t, err)

	require.NoError(t, watcher.Add(path))
	require.NoError(t, watcher.Start(context.Background()))

	t.Cleanup(func() {
		require.NoError(t, watcher.Stop(context.Background()))
	})

	require.NoError(t, os.Remove(path))

	requireEventuallyReceives(t, events, Event{
		Path: filepath.Clean(path),
		Op:   OpDeleted,
	})
}

func TestWatcherIntegrationObservesDirectoryChildCreation(t *testing.T) {
	t.Parallel()

	events := make(chan Event, 16)
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")

	watcher, err := New(EventHandlerFunc(func(evt Event) error {
		events <- evt

		return nil
	}), WithLogger(zerolog.Nop()))
	require.NoError(t, err)

	require.NoError(t, watcher.Add(dir))
	require.NoError(t, watcher.Start(context.Background()))

	t.Cleanup(func() {
		require.NoError(t, watcher.Stop(context.Background()))
	})

	require.NoError(t, os.WriteFile(path, []byte("rules"), 0o600))

	requireEventuallyReceives(t, events, Event{
		Path: filepath.Clean(path),
		Op:   OpAdded,
	})
}

func TestWatcherIntegrationObservesDirectoryChildChange(t *testing.T) {
	t.Parallel()

	events := make(chan Event, 16)
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")

	require.NoError(t, os.WriteFile(path, []byte("initial"), 0o600))

	watcher, err := New(EventHandlerFunc(func(evt Event) error {
		events <- evt

		return nil
	}), WithLogger(zerolog.Nop()))
	require.NoError(t, err)

	require.NoError(t, watcher.Add(dir))
	require.NoError(t, watcher.Start(context.Background()))

	t.Cleanup(func() {
		require.NoError(t, watcher.Stop(context.Background()))
	})

	require.NoError(t, os.WriteFile(path, []byte("updated"), 0o600))

	requireEventuallyReceives(t, events, Event{
		Path: filepath.Clean(path),
		Op:   OpChanged,
	})
}

func TestWatcherIntegrationObservesDirectoryChildDeletion(t *testing.T) {
	t.Parallel()

	events := make(chan Event, 16)
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")

	require.NoError(t, os.WriteFile(path, []byte("rules"), 0o600))

	watcher, err := New(EventHandlerFunc(func(evt Event) error {
		events <- evt

		return nil
	}), WithLogger(zerolog.Nop()))
	require.NoError(t, err)

	require.NoError(t, watcher.Add(dir))
	require.NoError(t, watcher.Start(context.Background()))

	t.Cleanup(func() {
		require.NoError(t, watcher.Stop(context.Background()))
	})

	require.NoError(t, os.Remove(path))

	requireEventuallyReceives(t, events, Event{
		Path: filepath.Clean(path),
		Op:   OpDeleted,
	})
}

func TestWatcherIntegrationObservesFileSymlinkTargetChange(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("symlink based test")
	}

	events := make(chan Event, 16)
	dir := t.TempDir()

	firstDataDir := filepath.Join(dir, "1")
	secondDataDir := filepath.Join(dir, "2")
	dataLink := filepath.Join(dir, "data")
	nextDataLink := filepath.Join(dir, "data_tmp")
	path := filepath.Join(dir, "file.txt")

	require.NoError(t, os.Mkdir(firstDataDir, 0o755))
	require.NoError(t, os.Mkdir(secondDataDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(firstDataDir, "file.txt"), []byte("initial"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(secondDataDir, "file.txt"), []byte("updated"), 0o600))
	require.NoError(t, os.Symlink(firstDataDir, dataLink))
	require.NoError(t, os.Symlink(filepath.Join("data", "file.txt"), path))

	watcher, err := New(EventHandlerFunc(func(evt Event) error {
		events <- evt

		return nil
	}), WithLogger(zerolog.Nop()))
	require.NoError(t, err)

	require.NoError(t, watcher.Add(path))
	require.NoError(t, watcher.Start(context.Background()))

	t.Cleanup(func() {
		require.NoError(t, watcher.Stop(context.Background()))
	})

	require.NoError(t, os.Symlink(secondDataDir, nextDataLink))
	require.NoError(t, os.Rename(nextDataLink, dataLink))
	require.NoError(t, os.RemoveAll(firstDataDir))

	requireEventuallyReceives(t, events, Event{
		Path: filepath.Clean(path),
		Op:   OpChanged,
	})
}

func TestWatcherIntegrationObservesDirectorySymlinkTargetChange(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("symlink based test")
	}

	events := make(chan Event, 16)
	dir := t.TempDir()

	firstDataDir := filepath.Join(dir, "1")
	secondDataDir := filepath.Join(dir, "2")
	dataLink := filepath.Join(dir, "data")
	nextDataLink := filepath.Join(dir, "data_tmp")
	path := filepath.Join(dir, "rules")

	require.NoError(t, os.MkdirAll(filepath.Join(firstDataDir, "rules"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(secondDataDir, "rules"), 0o755))
	require.NoError(t, os.Symlink(firstDataDir, dataLink))
	require.NoError(t, os.Symlink(filepath.Join("data", "rules"), path))

	watcher, err := New(EventHandlerFunc(func(evt Event) error {
		events <- evt

		return nil
	}), WithLogger(zerolog.Nop()))
	require.NoError(t, err)

	require.NoError(t, watcher.Add(path))
	require.NoError(t, watcher.Start(context.Background()))

	t.Cleanup(func() {
		require.NoError(t, watcher.Stop(context.Background()))
	})

	require.NoError(t, os.Symlink(secondDataDir, nextDataLink))
	require.NoError(t, os.Rename(nextDataLink, dataLink))
	require.NoError(t, os.RemoveAll(firstDataDir))

	requireEventuallyReceives(t, events, Event{
		Path: filepath.Clean(path),
		Op:   OpChanged,
	})
}

func TestWatcherIntegrationObservesDirectorySymlinkTargetChangeWithoutEmittingAddedForExistingFiles(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("symlink based test")
	}

	events := make(chan Event, 16)
	dir := t.TempDir()

	firstDataDir := filepath.Join(dir, "1")
	secondDataDir := filepath.Join(dir, "2")
	dataLink := filepath.Join(dir, "data")
	nextDataLink := filepath.Join(dir, "data_tmp")
	path := filepath.Join(dir, "rules")
	firstRulesDir := filepath.Join(firstDataDir, "rules")
	secondRulesDir := filepath.Join(secondDataDir, "rules")

	require.NoError(t, os.MkdirAll(firstRulesDir, 0o755))
	require.NoError(t, os.MkdirAll(secondRulesDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(firstRulesDir, "first.yaml"), []byte("first"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(firstRulesDir, "second.yaml"), []byte("second"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(secondRulesDir, "third.yaml"), []byte("third"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(secondRulesDir, "fourth.yaml"), []byte("fourth"), 0o600))
	require.NoError(t, os.Symlink(firstDataDir, dataLink))
	require.NoError(t, os.Symlink(filepath.Join("data", "rules"), path))

	watcher, err := New(EventHandlerFunc(func(evt Event) error {
		events <- evt

		return nil
	}), WithLogger(zerolog.Nop()))
	require.NoError(t, err)

	require.NoError(t, watcher.Add(path))
	require.NoError(t, watcher.Start(context.Background()))

	t.Cleanup(func() {
		require.NoError(t, watcher.Stop(context.Background()))
	})

	require.NoError(t, os.Symlink(secondDataDir, nextDataLink))
	require.NoError(t, os.Rename(nextDataLink, dataLink))
	require.NoError(t, os.RemoveAll(firstDataDir))

	requireEventuallyReceives(t, events, Event{
		Path: filepath.Clean(path),
		Op:   OpChanged,
	})

	requireNeverReceives(t, events,
		Event{Path: filepath.Join(path, "third.yaml"), Op: OpAdded},
		Event{Path: filepath.Join(path, "fourth.yaml"), Op: OpAdded},
	)
}

func requireNeverReceives(t *testing.T, events <-chan Event, unexpected ...Event) {
	t.Helper()

	require.Never(t, func() bool {
		for {
			select {
			case evt := <-events:
				return slices.Contains(unexpected, evt)
			default:
				return false
			}
		}
	}, 200*time.Millisecond, 10*time.Millisecond)
}

func requireEventuallyReceives(t *testing.T, events <-chan Event, expected Event) {
	t.Helper()

	require.Eventually(t, func() bool {
		for {
			select {
			case evt := <-events:
				if evt == expected {
					return true
				}
			default:
				return false
			}
		}
	}, 2*time.Second, 10*time.Millisecond)
}
