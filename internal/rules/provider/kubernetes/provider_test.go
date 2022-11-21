package kubernetes

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"

	"github.com/dadrus/heimdall/internal/rules/event"
)

func TestFoo(t *testing.T) {
	t.SkipNow()

	config, err := clientcmd.BuildConfigFromFlags("", filepath.Join(homedir.HomeDir(), ".kube", "config"))
	require.NoError(t, err)

	queue := make(event.RuleSetChangedEventQueue, 10)
	defer close(queue)

	prov, err := newProvider(map[string]any{"auth_class": "foobar"}, config, queue, log.Logger)
	require.NoError(t, err)

	err = prov.Start(context.Background())
	require.NoError(t, err)

	time.Sleep(15 * time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = prov.Stop(ctx)
	require.NoError(t, err)
}
