package redis

import (
	"context"
	"fmt"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestNewStandaloneCache(t *testing.T) {
	t.Parallel()

	db := miniredis.RunT(t)

	for _, tc := range []struct {
		uc     string
		config []byte
		assert func(t *testing.T, err error, cch cache.Cache)
	}{
		{
			uc:     "empty config",
			config: []byte(``),
			assert: func(t *testing.T, err error, _ cache.Cache) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "'address' is a required field")
			},
		},
		{
			uc:     "empty address provided",
			config: []byte(`address: ""`),
			assert: func(t *testing.T, err error, _ cache.Cache) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "'address' is a required field")
			},
		},
		{
			uc:     "config contains unsupported properties",
			config: []byte(`foo: bar`),
			assert: func(t *testing.T, err error, _ cache.Cache) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "failed decoding redis cache config")
			},
		},
		{
			uc:     "not existing address provided",
			config: []byte(`address: "foo.local:12345"`),
			assert: func(t *testing.T, err error, _ cache.Cache) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				require.ErrorContains(t, err, "failed creating redis client")
			},
		},
		{
			uc:     "successful cache creation",
			config: []byte(fmt.Sprintf("{address: %s, client_cache: {disabled: true}}", db.Addr())),
			assert: func(t *testing.T, err error, cch cache.Cache) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, cch)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			// WHEN
			cch, err := NewStandaloneCache(conf)
			if err == nil {
				defer cch.Stop(context.TODO())
			}

			// THEN
			tc.assert(t, err, cch)
		})
	}
}
