package kubernetes

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/event"
	"github.com/dadrus/heimdall/internal/testsupport"
)

func TestNewProvider(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		conf   []byte
		assert func(t *testing.T, err error, prov *provider)
	}{
		{
			uc:   "with unknown field",
			conf: []byte(`foo: bar`),
			assert: func(t *testing.T, err error, prov *provider) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to decode")
			},
		},
		{
			uc:   "with empty configuration",
			conf: []byte(`{}`),
			assert: func(t *testing.T, err error, prov *provider) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, prov)
				assert.Equal(t, DefaultClass, prov.ac)
				assert.Nil(t, prov.cancel)
				assert.NotNil(t, prov.cl)
			},
		},
		{
			uc:   "with auth_class configured",
			conf: []byte(`auth_class: foo`),
			assert: func(t *testing.T, err error, prov *provider) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, prov)
				assert.Equal(t, "foo", prov.ac)
				assert.Nil(t, prov.cancel)
				assert.NotNil(t, prov.cl)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			providerConf, err := testsupport.DecodeTestConfig(tc.conf)
			require.NoError(t, err)

			queue := make(event.RuleSetChangedEventQueue, 10)

			// WHEN
			prov, err := newProvider(providerConf, &rest.Config{Host: "http://localhost:80001"}, queue, log.Logger)

			// THEN
			tc.assert(t, err, prov)
		})
	}
}

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

	time.Sleep(150 * time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = prov.Stop(ctx)
	require.NoError(t, err)
}
