package cloudblob

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3mem"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/event"
	"github.com/dadrus/heimdall/internal/testsupport"
	"github.com/dadrus/heimdall/internal/x"
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
			uc:   "without buckets",
			conf: []byte(`watch_interval: 5s`),
			assert: func(t *testing.T, err error, prov *provider) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "no buckets configured")
			},
		},
		{
			uc: "without url in one of the configured bucket",
			conf: []byte(`
buckets:
  - url: s3://foobar
  - prefix: bar
`),
			assert: func(t *testing.T, err error, prov *provider) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "missing url for #1")
			},
		},
		{
			uc: "with watch interval and unsupported property in one of the buckets configured",
			conf: []byte(`
watch_interval: 5s
buckets:
  - url: s3://foobar
  - foo: bar
`),
			assert: func(t *testing.T, err error, prov *provider) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to decode")
			},
		},
		{
			uc: "with watch interval and two buckets configured",
			conf: []byte(`
watch_interval: 5s
buckets:
  - url: s3://foobar
  - url: s3://barfoo/foo&foo=bar
    prefix: bar
    rules_path_prefix: baz
`),
			assert: func(t *testing.T, err error, prov *provider) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, prov)
				assert.NotNil(t, prov.s)
				assert.NotNil(t, prov.q)
				assert.NotNil(t, prov.cancel)
				assert.False(t, prov.s.IsRunning())
				assert.Len(t, prov.s.Jobs(), 2)
				assert.False(t, prov.s.Jobs()[0].IsRunning())
				assert.False(t, prov.s.Jobs()[1].IsRunning())
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			providerConf, err := testsupport.DecodeTestConfig(tc.conf)
			require.NoError(t, err)

			queue := make(event.RuleSetChangedEventQueue, 10)

			// WHEN
			prov, err := newProvider(providerConf, queue, log.Logger)

			// THEN
			tc.assert(t, err, prov)
		})
	}
}

func TestProviderLifecycle(t *testing.T) { //nolint:maintidx
	// aws is not used, but an aws s3 compatible implementation
	// however, since the aws sdk is used to talk to it,
	// it expects credentials, even these are not used at the end
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")

	bucketName := "new_bucket"
	backend := s3mem.New()
	s3 := gofakes3.New(backend)
	srv := httptest.NewServer(s3.Server())

	defer srv.Close()

	require.NoError(t, backend.CreateBucket(bucketName))

	clearBucket := func(t *testing.T) {
		t.Helper()

		objList, err := backend.ListBucket(bucketName, nil, gofakes3.ListBucketPage{})
		require.NoError(t, err)

		for _, obj := range objList.Contents {
			_, err := backend.DeleteObject(bucketName, obj.Key)
			require.NoError(t, err)
		}
	}

	type testCase struct {
		uc          string
		conf        []byte
		setupBucket func(t *testing.T)
		assert      func(t *testing.T, tc testCase, logs fmt.Stringer, queue event.RuleSetChangedEventQueue)
	}

	for _, tc := range []testCase{
		{
			uc: "with rule set loading error due to DNS error",
			conf: []byte(`
buckets:
- url: s3://foo?endpoint=does-not-exist.local&region=eu-central-1
`),
			assert: func(t *testing.T, tc testCase, logs fmt.Stringer, queue event.RuleSetChangedEventQueue) {
				t.Helper()

				time.Sleep(500 * time.Millisecond)

				messages := logs.String()
				assert.Contains(t, messages, "communication error")
				assert.Contains(t, messages, "Failed to fetch rule set")
				assert.Contains(t, messages, "name resolution")
				assert.Contains(t, messages, "No updates received")
			},
		},
		{
			uc: "with no blobs in the bucket",
			conf: []byte(`
buckets:
- url: s3://` + bucketName + `?endpoint=` + srv.URL + `&disableSSL=true&s3ForcePathStyle=true&region=eu-central-1
`),
			assert: func(t *testing.T, tc testCase, logs fmt.Stringer, queue event.RuleSetChangedEventQueue) {
				t.Helper()

				time.Sleep(250 * time.Millisecond)

				messages := logs.String()
				assert.NotContains(t, messages, "error")
				assert.Contains(t, messages, "No updates received")
			},
		},
		{
			uc: "with an empty blob in the bucket",
			conf: []byte(`
buckets:
- url: s3://` + bucketName + `?endpoint=` + srv.URL + `&disableSSL=true&s3ForcePathStyle=true&region=eu-central-1
`),
			setupBucket: func(t *testing.T) {
				t.Helper()

				_, err := backend.PutObject(bucketName, "test-rule",
					map[string]string{"Content-Type": "application/json"},
					strings.NewReader(``), 0)
				require.NoError(t, err)
			},
			assert: func(t *testing.T, tc testCase, logs fmt.Stringer, queue event.RuleSetChangedEventQueue) {
				t.Helper()

				time.Sleep(250 * time.Millisecond)

				messages := logs.String()
				assert.NotContains(t, messages, "error")
				assert.Contains(t, messages, "No updates received")
			},
		},
		{
			uc: "with not empty blob and without watch interval",
			conf: []byte(`
buckets:
- url: s3://` + bucketName + `?endpoint=` + srv.URL + `&disableSSL=true&s3ForcePathStyle=true&region=eu-central-1
`),
			setupBucket: func(t *testing.T) {
				t.Helper()

				data := "- id: foo"

				_, err := backend.PutObject(bucketName, "test-rule",
					map[string]string{"Content-Type": "application/yaml"},
					strings.NewReader(data), int64(len(data)))
				require.NoError(t, err)
			},
			assert: func(t *testing.T, tc testCase, logs fmt.Stringer, queue event.RuleSetChangedEventQueue) {
				t.Helper()

				time.Sleep(600 * time.Millisecond)

				assert.NotContains(t, logs.String(), "No updates received")

				require.Len(t, queue, 1)

				evt := <-queue
				assert.Contains(t, evt.Src, "blob:test-rule@s3")
				assert.Len(t, evt.RuleSet, 1)
				assert.Equal(t, "foo", evt.RuleSet[0].ID)
				assert.Equal(t, event.Create, evt.ChangeType)
			},
		},
		{
			uc: "with not empty server response and with watch interval",
			conf: []byte(`
watch_interval: 250ms
buckets:
- url: s3://` + bucketName + `?endpoint=` + srv.URL + `&disableSSL=true&s3ForcePathStyle=true&region=eu-central-1
`),
			setupBucket: func(t *testing.T) {
				t.Helper()

				data := "- id: foo"

				_, err := backend.PutObject(bucketName, "test-rule",
					map[string]string{"Content-Type": "application/yaml"},
					strings.NewReader(data), int64(len(data)))
				require.NoError(t, err)
			},
			assert: func(t *testing.T, tc testCase, logs fmt.Stringer, queue event.RuleSetChangedEventQueue) {
				t.Helper()

				time.Sleep(600 * time.Millisecond)

				assert.Contains(t, logs.String(), "No updates received")

				require.Len(t, queue, 1)

				evt := <-queue
				assert.Contains(t, evt.Src, "blob:test-rule@s3")
				assert.Len(t, evt.RuleSet, 1)
				assert.Equal(t, "foo", evt.RuleSet[0].ID)
				assert.Equal(t, event.Create, evt.ChangeType)
			},
		},
		{
			uc: "first request successful, second request with empty bucket, successive requests successful without changes",
			conf: []byte(`
watch_interval: 250ms
buckets:
- url: s3://` + bucketName + `?endpoint=` + srv.URL + `&disableSSL=true&s3ForcePathStyle=true&region=eu-central-1
`),
			setupBucket: func() func(t *testing.T) {
				callIdx := 1

				return func(t *testing.T) {
					t.Helper()

					switch callIdx {
					case 1:
						data := "- id: foo"

						_, err := backend.PutObject(bucketName, "test-rule1",
							map[string]string{"Content-Type": "application/yaml"},
							strings.NewReader(data), int64(len(data)))
						require.NoError(t, err)
					case 2:
						clearBucket(t)
					default:
						data := "- id: bar"

						_, err := backend.PutObject(bucketName, "test-rule2",
							map[string]string{"Content-Type": "application/yaml"},
							strings.NewReader(data), int64(len(data)))
						require.NoError(t, err)
					}

					callIdx++
				}
			}(),
			assert: func(t *testing.T, tc testCase, logs fmt.Stringer, queue event.RuleSetChangedEventQueue) {
				t.Helper()

				time.Sleep(150 * time.Millisecond)
				tc.setupBucket(t)
				time.Sleep(250 * time.Millisecond)
				tc.setupBucket(t)
				time.Sleep(250 * time.Millisecond)
				tc.setupBucket(t)
				time.Sleep(250 * time.Millisecond)
				tc.setupBucket(t)
				time.Sleep(250 * time.Millisecond)

				assert.Contains(t, logs.String(), "No updates received")

				require.Len(t, queue, 3)

				evt := <-queue
				assert.Contains(t, evt.Src, "blob:test-rule1@s3")
				assert.Len(t, evt.RuleSet, 1)
				assert.Equal(t, "foo", evt.RuleSet[0].ID)
				assert.Equal(t, event.Create, evt.ChangeType)

				evt = <-queue
				assert.Contains(t, evt.Src, "blob:test-rule1@s3")
				assert.Len(t, evt.RuleSet, 0)
				assert.Equal(t, event.Remove, evt.ChangeType)

				evt = <-queue
				assert.Contains(t, evt.Src, "blob:test-rule2@s3")
				assert.Len(t, evt.RuleSet, 1)
				assert.Equal(t, "bar", evt.RuleSet[0].ID)
				assert.Equal(t, event.Create, evt.ChangeType)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			clearBucket(t)

			setupBucket := x.IfThenElse(tc.setupBucket != nil, tc.setupBucket, func(t *testing.T) { t.Helper() })

			providerConf, err := testsupport.DecodeTestConfig(tc.conf)
			require.NoError(t, err)

			queue := make(event.RuleSetChangedEventQueue, 10)
			defer close(queue)

			logs := &strings.Builder{}
			prov, err := newProvider(providerConf, queue, zerolog.New(logs))
			require.NoError(t, err)

			ctx := context.Background()

			setupBucket(t)

			// WHEN
			err = prov.Start(ctx)

			defer prov.Stop(ctx) //nolint:errcheck

			// THEN
			require.NoError(t, err)
			tc.assert(t, tc, logs, queue)
		})
	}
}
