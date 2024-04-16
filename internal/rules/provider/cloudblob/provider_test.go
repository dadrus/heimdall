// Copyright 2022 Dimitrij Drus <dadrus@gmx.de>
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
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	config2 "github.com/dadrus/heimdall/internal/rules/config"
	"github.com/dadrus/heimdall/internal/rules/rule/mocks"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/testsupport"
	mock2 "github.com/dadrus/heimdall/internal/x/testsupport/mock"
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
			assert: func(t *testing.T, err error, _ *provider) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to decode")
			},
		},
		{
			uc:   "without buckets",
			conf: []byte(`watch_interval: 5s`),
			assert: func(t *testing.T, err error, _ *provider) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
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
			assert: func(t *testing.T, err error, _ *provider) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
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
			assert: func(t *testing.T, err error, _ *provider) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
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
    rule_path_match_prefix: baz
`),
			assert: func(t *testing.T, err error, prov *provider) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, prov)
				assert.NotNil(t, prov.s)
				assert.NotNil(t, prov.p)
				assert.NotNil(t, prov.cancel)

				time.Sleep(250 * time.Millisecond)

				jobs := prov.s.Jobs()
				assert.Len(t, jobs, 2)
				lr, err := jobs[0].LastRun()
				require.NoError(t, err)
				assert.True(t, lr.IsZero())
				lr, err = jobs[1].LastRun()
				require.NoError(t, err)
				assert.True(t, lr.IsZero())
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			providerConf, err := testsupport.DecodeTestConfig(tc.conf)
			require.NoError(t, err)

			conf := &config.Configuration{
				Providers: config.RuleProviders{CloudBlob: providerConf},
			}

			// WHEN
			prov, err := newProvider(conf, mocks.NewRuleSetProcessorMock(t), log.Logger)

			// THEN
			tc.assert(t, err, prov)
		})
	}
}

func TestProviderLifecycle(t *testing.T) {
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
		uc             string
		conf           []byte
		setupBucket    func(t *testing.T)
		setupProcessor func(t *testing.T, processor *mocks.RuleSetProcessorMock)
		assert         func(t *testing.T, tc testCase, logs fmt.Stringer, processor *mocks.RuleSetProcessorMock)
	}

	for _, tc := range []testCase{
		{
			uc: "with no blobs in the bucket",
			conf: []byte(`
buckets:
- url: s3://` + bucketName + `?endpoint=` + srv.URL + `&disableSSL=true&s3ForcePathStyle=true&region=eu-central-1
`),
			assert: func(t *testing.T, _ testCase, logs fmt.Stringer, _ *mocks.RuleSetProcessorMock) {
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
			assert: func(t *testing.T, _ testCase, logs fmt.Stringer, _ *mocks.RuleSetProcessorMock) {
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

				data := `
version: "1"
name: test
rules:
- id: foo
  match:
    path: /foo
`

				_, err := backend.PutObject(bucketName, "test-rule",
					map[string]string{"Content-Type": "application/yaml"},
					strings.NewReader(data), int64(len(data)))
				require.NoError(t, err)
			},
			setupProcessor: func(t *testing.T, processor *mocks.RuleSetProcessorMock) {
				t.Helper()

				processor.EXPECT().OnCreated(mock.Anything).
					Run(mock2.NewArgumentCaptor[*config2.RuleSet](&processor.Mock, "captor1").Capture).
					Return(nil).Once()
			},
			assert: func(t *testing.T, _ testCase, logs fmt.Stringer, processor *mocks.RuleSetProcessorMock) {
				t.Helper()

				time.Sleep(600 * time.Millisecond)

				assert.NotContains(t, logs.String(), "No updates received")

				ruleSet := mock2.ArgumentCaptorFrom[*config2.RuleSet](&processor.Mock, "captor1").Value()
				assert.Contains(t, ruleSet.Source, "test-rule@s3://"+bucketName)
				assert.Equal(t, "1", ruleSet.Version)
				assert.Len(t, ruleSet.Rules, 1)
				assert.Equal(t, "foo", ruleSet.Rules[0].ID)
				assert.Contains(t, ruleSet.Source, "test-rule@s3")
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

				data := `
version: "1"
name: test
rules:
- id: foo
  match:
    path: /foo
`

				_, err := backend.PutObject(bucketName, "test-rule",
					map[string]string{"Content-Type": "application/yaml"},
					strings.NewReader(data), int64(len(data)))
				require.NoError(t, err)
			},
			setupProcessor: func(t *testing.T, processor *mocks.RuleSetProcessorMock) {
				t.Helper()

				processor.EXPECT().OnCreated(mock.Anything).
					Run(mock2.NewArgumentCaptor[*config2.RuleSet](&processor.Mock, "captor1").Capture).
					Return(nil).Once()
			},
			assert: func(t *testing.T, _ testCase, logs fmt.Stringer, processor *mocks.RuleSetProcessorMock) {
				t.Helper()

				time.Sleep(600 * time.Millisecond)

				assert.Contains(t, logs.String(), "No updates received")

				ruleSet := mock2.ArgumentCaptorFrom[*config2.RuleSet](&processor.Mock, "captor1").Value()
				assert.Contains(t, ruleSet.Source, "test-rule@s3://"+bucketName)
				assert.Equal(t, "1", ruleSet.Version)
				assert.Len(t, ruleSet.Rules, 1)
				assert.Equal(t, "foo", ruleSet.Rules[0].ID)
				assert.Contains(t, ruleSet.Source, "test-rule@s3")
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
						data := `
version: "1"
name: test
rules:
- id: foo
  match:
    path: /foo
`

						_, err := backend.PutObject(bucketName, "test-rule1",
							map[string]string{"Content-Type": "application/yaml"},
							strings.NewReader(data), int64(len(data)))
						require.NoError(t, err)
					case 2:
						clearBucket(t)
					default:
						data := `
version: "1"
name: test
rules:
- id: bar
  match:
    path: /bar
`

						_, err := backend.PutObject(bucketName, "test-rule2",
							map[string]string{"Content-Type": "application/yaml"},
							strings.NewReader(data), int64(len(data)))
						require.NoError(t, err)
					}

					callIdx++
				}
			}(),
			setupProcessor: func(t *testing.T, processor *mocks.RuleSetProcessorMock) {
				t.Helper()

				processor.EXPECT().OnCreated(mock.Anything).
					Run(mock2.NewArgumentCaptor[*config2.RuleSet](&processor.Mock, "captor1").Capture).
					Return(nil).Twice()

				processor.EXPECT().OnDeleted(mock.Anything).
					Run(mock2.NewArgumentCaptor[*config2.RuleSet](&processor.Mock, "captor2").Capture).
					Return(nil).Once()
			},
			assert: func(t *testing.T, tc testCase, logs fmt.Stringer, processor *mocks.RuleSetProcessorMock) {
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

				ruleSets := mock2.ArgumentCaptorFrom[*config2.RuleSet](&processor.Mock, "captor1").Values()
				require.Len(t, ruleSets, 2)
				assert.Equal(t, "foo", ruleSets[0].Rules[0].ID)
				assert.Contains(t, ruleSets[0].Source, "test-rule1@s3")
				assert.Equal(t, "1", ruleSets[0].Version)
				assert.Len(t, ruleSets[0].Rules, 1)
				assert.Contains(t, ruleSets[1].Source, "test-rule2@s3")
				assert.Equal(t, "1", ruleSets[1].Version)
				assert.Len(t, ruleSets[1].Rules, 1)
				assert.Equal(t, "bar", ruleSets[1].Rules[0].ID)

				ruleSet := mock2.ArgumentCaptorFrom[*config2.RuleSet](&processor.Mock, "captor2").Value()
				assert.Contains(t, ruleSet.Source, "test-rule1@s3")
			},
		},
		{
			uc: "rule set change",
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
						data := `
version: "1"
name: test
rules:
- id: foo
  match:
    path: /foo
`

						_, err := backend.PutObject(bucketName, "test-rule",
							map[string]string{"Content-Type": "application/yaml"},
							strings.NewReader(data), int64(len(data)))
						require.NoError(t, err)
					case 2:
						data := `
version: "1"
name: test
rules:
- id: bar
  match:
    path: /bar
`

						_, err := backend.PutObject(bucketName, "test-rule",
							map[string]string{"Content-Type": "application/yaml"},
							strings.NewReader(data), int64(len(data)))
						require.NoError(t, err)
					default:
						data := `
version: "1"
name: test
rules:
- id: baz
  match:
    path: /baz
`

						_, err := backend.PutObject(bucketName, "test-rule",
							map[string]string{"Content-Type": "application/yaml"},
							strings.NewReader(data), int64(len(data)))
						require.NoError(t, err)
					}

					callIdx++
				}
			}(),
			setupProcessor: func(t *testing.T, processor *mocks.RuleSetProcessorMock) {
				t.Helper()

				processor.EXPECT().OnCreated(mock.Anything).
					Run(mock2.NewArgumentCaptor[*config2.RuleSet](&processor.Mock, "captor1").Capture).
					Return(nil).Once()
				processor.EXPECT().OnUpdated(mock.Anything).
					Run(mock2.NewArgumentCaptor[*config2.RuleSet](&processor.Mock, "captor2").Capture).
					Return(nil).Twice()
			},
			assert: func(t *testing.T, tc testCase, logs fmt.Stringer, processor *mocks.RuleSetProcessorMock) {
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

				ruleSet := mock2.ArgumentCaptorFrom[*config2.RuleSet](&processor.Mock, "captor1").Value()
				assert.Equal(t, "foo", ruleSet.Rules[0].ID)
				assert.Contains(t, ruleSet.Source, "test-rule@s3")
				assert.Len(t, ruleSet.Rules, 1)

				ruleSets := mock2.ArgumentCaptorFrom[*config2.RuleSet](&processor.Mock, "captor2").Values()
				assert.Len(t, ruleSets, 2)
				assert.Contains(t, ruleSets[0].Source, "test-rule@s3")
				assert.Equal(t, "1", ruleSets[0].Version)
				assert.Len(t, ruleSets[0].Rules, 1)
				assert.Equal(t, "bar", ruleSets[0].Rules[0].ID)
				assert.Contains(t, ruleSets[1].Source, "test-rule@s3")
				assert.Equal(t, "1", ruleSets[1].Version)
				assert.Len(t, ruleSets[1].Rules, 1)
				assert.Equal(t, "baz", ruleSets[1].Rules[0].ID)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			clearBucket(t)

			setupBucket := x.IfThenElse(
				tc.setupBucket != nil,
				tc.setupBucket,
				func(t *testing.T) { t.Helper() },
			)
			setupProcessor := x.IfThenElse(
				tc.setupProcessor != nil,
				tc.setupProcessor,
				func(t *testing.T, _ *mocks.RuleSetProcessorMock) { t.Helper() },
			)

			providerConf, err := testsupport.DecodeTestConfig(tc.conf)
			require.NoError(t, err)

			mock := mocks.NewRuleSetProcessorMock(t)
			setupProcessor(t, mock)

			conf := &config.Configuration{
				Providers: config.RuleProviders{CloudBlob: providerConf},
			}

			logs := &strings.Builder{}
			prov, err := newProvider(conf, mock, zerolog.New(logs))
			require.NoError(t, err)

			ctx := context.Background()

			setupBucket(t)

			// WHEN
			err = prov.Start(ctx)

			defer prov.Stop(ctx) //nolint:errcheck

			// THEN
			require.NoError(t, err)
			tc.assert(t, tc, logs, mock)
		})
	}
}
