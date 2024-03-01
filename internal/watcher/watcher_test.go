package watcher

import (
	"context"
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

	cw.Start(context.TODO())
	defer cw.Stop(context.TODO())

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

	// THEN
	cl1.AssertExpectations(t)
	cl2.AssertExpectations(t)
	cl3.AssertExpectations(t)
	cl4.AssertExpectations(t)
}
