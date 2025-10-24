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
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3mem"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/api/v1beta1"
	"github.com/dadrus/heimdall/internal/validation"
	"github.com/dadrus/heimdall/internal/x"
)

func TestFetchRuleSets(t *testing.T) {
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

	for uc, tc := range map[string]struct {
		endpoint ruleSetEndpoint
		setup    func(t *testing.T)
		assert   func(t *testing.T, err error, ruleSets []*v1beta1.RuleSet)
	}{
		"failed to open bucket": {
			endpoint: ruleSetEndpoint{
				URL: &url.URL{
					Scheme:   "s3",
					Host:     "foo",
					RawQuery: "endpoint=does-not-exist.local&foo=bar&region=eu-central-1",
				},
			},
			assert: func(t *testing.T, err error, _ []*v1beta1.RuleSet) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				require.ErrorContains(t, err, "failed to open bucket")
			},
		},
		"iterate not existing bucket": {
			endpoint: ruleSetEndpoint{
				URL: &url.URL{
					Scheme:   "s3",
					Host:     "foo",
					RawQuery: fmt.Sprintf("endpoint=%s&region=eu-central-1", srv.URL),
				},
			},
			assert: func(t *testing.T, err error, _ []*v1beta1.RuleSet) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrCommunication)
				require.ErrorContains(t, err, "failed iterate blobs")
			},
		},
		"invalid rule set": {
			endpoint: ruleSetEndpoint{
				URL: &url.URL{
					Scheme:   "s3",
					Host:     bucketName,
					RawQuery: fmt.Sprintf("endpoint=%s&region=eu-central-1", srv.URL),
				},
			},
			setup: func(t *testing.T) {
				t.Helper()

				data := `{"test":"foo"}`

				_, err := backend.PutObject(bucketName, "test-rule",
					map[string]string{"Content-Type": "application/json"},
					strings.NewReader(data), int64(len(data)), nil)
				require.NoError(t, err)
			},
			assert: func(t *testing.T, err error, _ []*v1beta1.RuleSet) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				require.ErrorContains(t, err, "failed to decode")
			},
		},
		"empty bucket": {
			endpoint: ruleSetEndpoint{
				URL: &url.URL{
					Scheme:   "s3",
					Host:     bucketName,
					RawQuery: fmt.Sprintf("endpoint=%s&region=eu-central-1", srv.URL),
				},
			},
			assert: func(t *testing.T, err error, ruleSets []*v1beta1.RuleSet) {
				t.Helper()

				require.NoError(t, err)
				require.Empty(t, ruleSets)
			},
		},
		"bucket with an empty blob": {
			endpoint: ruleSetEndpoint{
				URL: &url.URL{
					Scheme:   "s3",
					Host:     bucketName,
					RawQuery: fmt.Sprintf("endpoint=%s&region=eu-central-1", srv.URL),
				},
			},
			setup: func(t *testing.T) {
				t.Helper()

				_, err := backend.PutObject(bucketName, "test-rule",
					map[string]string{"Content-Type": "application/json"},
					strings.NewReader(""), 0, nil)
				require.NoError(t, err)
			},
			assert: func(t *testing.T, err error, ruleSets []*v1beta1.RuleSet) {
				t.Helper()

				require.NoError(t, err)
				require.Empty(t, ruleSets)
			},
		},
		"multiple valid rule sets in yaml and json formats": {
			endpoint: ruleSetEndpoint{
				URL: &url.URL{
					Scheme:   "s3",
					Host:     bucketName,
					RawQuery: fmt.Sprintf("endpoint=%s&region=eu-central-1", srv.URL),
				},
			},
			setup: func(t *testing.T) {
				t.Helper()

				ruleSet1 := `
{
	"version": "1",
	"name": "test",
	"rules": [{
		"id": "foobar",
        "match": {
          "routes": [
            { "path": "/foo/bar/api1" }
          ],
          "scheme": "http",
          "hosts": [ "*.example.com" ],
          "methods": ["GET", "POST"]
        },
		"execute": [
			{ "authenticator": "foobar" }
		]
	}]
}`

				ruleSet2 := `
version: "1"
name: test2
rules:
- id: barfoo
  match:
    routes:
      - path: /foo/bar/api2
    scheme: http
    hosts:
      - "*.example.com"
    methods: 
      - GET
      - POST
  execute:
  - authenticator: barfoo
`
				_, err := backend.PutObject(bucketName, "test-rule1",
					map[string]string{"Content-Type": "application/json"},
					strings.NewReader(ruleSet1), int64(len(ruleSet1)), nil)
				require.NoError(t, err)

				_, err = backend.PutObject(bucketName, "test-rule2",
					map[string]string{"Content-Type": "application/yaml"},
					strings.NewReader(ruleSet2), int64(len(ruleSet2)), nil)
				require.NoError(t, err)
			},
			assert: func(t *testing.T, err error, ruleSets []*v1beta1.RuleSet) {
				t.Helper()

				require.NoError(t, err)

				require.Len(t, ruleSets, 2)

				assert.Contains(t, ruleSets[0].Source, "test-rule1")
				assert.NotEmpty(t, ruleSets[0].Hash)
				assert.Len(t, ruleSets[0].Rules, 1)
				assert.Equal(t, "foobar", ruleSets[0].Rules[0].ID)

				assert.Contains(t, ruleSets[1].Source, "test-rule2")
				assert.NotEmpty(t, ruleSets[1].Hash)
				assert.Len(t, ruleSets[1].Rules, 1)
				assert.Equal(t, "barfoo", ruleSets[1].Rules[0].ID)
			},
		},
		"only one rule set adhering to the required prefix": {
			endpoint: ruleSetEndpoint{
				URL: &url.URL{
					Scheme:   "s3",
					Host:     bucketName,
					RawQuery: fmt.Sprintf("endpoint=%s&region=eu-central-1", srv.URL),
				},
				Prefix: "api",
			},
			setup: func(t *testing.T) {
				t.Helper()

				ruleSet1 := `{
				"version": "1",
				"name": "test1",
				"rules": [{
					"id": "foobar",
                    "match": {
                      "routes": [
                         { "path": "/foo/bar/api1" }
                      ],
                      "scheme": "http",
                      "hosts": ["example.com"],
                      "methods": ["GET", "POST"]
                    },
					"execute": [
						{ "authenticator": "foobar" }
					]
				}]}`

				ruleSet2 := `{
				"version": "1",
				"name": "test2",
				"rules": [{
					"id": "barfoo",
                    "match": {
                      "routes": [
                        { "path": "/foo/bar/api2" }
                      ],
                      "scheme": "http",
                      "hosts": [{ "type": "wildcard", "value": "*"}],
                      "methods": ["GET", "POST"]
                    },
					"execute": [
						{ "authenticator": "barfoo" }
					]
				}]}`

				_, err := backend.PutObject(bucketName, "api-rule",
					map[string]string{"Content-Type": "application/json"},
					strings.NewReader(ruleSet1), int64(len(ruleSet1)), nil)
				require.NoError(t, err)

				_, err = backend.PutObject(bucketName, "test-rule",
					map[string]string{"Content-Type": "application/json"},
					strings.NewReader(ruleSet2), int64(len(ruleSet2)), nil)
				require.NoError(t, err)
			},
			assert: func(t *testing.T, err error, ruleSets []*v1beta1.RuleSet) {
				t.Helper()

				require.NoError(t, err)

				require.Len(t, ruleSets, 1)

				assert.Contains(t, ruleSets[0].Source, "api-rule")
				assert.NotEmpty(t, ruleSets[0].Hash)
				assert.Len(t, ruleSets[0].Rules, 1)
				assert.Equal(t, "foobar", ruleSets[0].Rules[0].ID)
			},
		},
		"not existing rule set specified in the path": {
			endpoint: ruleSetEndpoint{
				URL: &url.URL{
					Scheme:   "s3",
					Host:     bucketName,
					Path:     "ruleset",
					RawQuery: fmt.Sprintf("endpoint=%s&region=eu-central-1", srv.URL),
				},
				Prefix: "api",
			},
			assert: func(t *testing.T, err error, _ []*v1beta1.RuleSet) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				require.ErrorContains(t, err, "attributes")
			},
		},
		"empty blob specified in the path": {
			endpoint: ruleSetEndpoint{
				URL: &url.URL{
					Scheme:   "s3",
					Host:     bucketName,
					Path:     "ruleset",
					RawQuery: fmt.Sprintf("endpoint=%s&region=eu-central-1", srv.URL),
				},
				Prefix: "api",
			},
			setup: func(t *testing.T) {
				t.Helper()

				_, err := backend.PutObject(bucketName, "ruleset",
					map[string]string{"Content-Type": "application/json"},
					strings.NewReader(""), 0, nil)
				require.NoError(t, err)
			},
			assert: func(t *testing.T, err error, ruleSets []*v1beta1.RuleSet) {
				t.Helper()

				require.NoError(t, err)
				assert.Empty(t, ruleSets)
			},
		},
		"existing rule set specified in the path": {
			endpoint: ruleSetEndpoint{
				URL: &url.URL{
					Scheme:   "s3",
					Host:     bucketName,
					Path:     "ruleset",
					RawQuery: fmt.Sprintf("endpoint=%s&region=eu-central-1", srv.URL),
				},
				Prefix: "api",
			},
			setup: func(t *testing.T) {
				t.Helper()

				ruleSet1 := `{
				"version": "1",
				"name": "test",
				"rules": [{
					"id": "foobar",
                    "match": {
                      "routes": [
                        { "path": "/foo/bar/api1" }
                      ],
                      "scheme": "http",
                      "hosts": ["example.com"],
                      "methods": ["GET", "POST"]
                    },
					"execute": [
						{ "authenticator": "foobar" }
					]
				}]}`

				_, err := backend.PutObject(bucketName, "ruleset",
					map[string]string{"Content-Type": "application/json"},
					strings.NewReader(ruleSet1), int64(len(ruleSet1)), nil)
				require.NoError(t, err)
			},
			assert: func(t *testing.T, err error, ruleSets []*v1beta1.RuleSet) {
				t.Helper()

				require.NoError(t, err)

				require.Len(t, ruleSets, 1)

				assert.Contains(t, ruleSets[0].Source, "ruleset")
				assert.NotEmpty(t, ruleSets[0].Hash)
				assert.Len(t, ruleSets[0].Rules, 1)
				assert.Equal(t, "foobar", ruleSets[0].Rules[0].ID)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			clearBucket(t)

			validator, err := validation.NewValidator()
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Validator().Maybe().Return(validator)

			setup := x.IfThenElse(tc.setup != nil, tc.setup, func(t *testing.T) { t.Helper() })
			setup(t)

			// WHEN
			rs, err := tc.endpoint.FetchRuleSets(t.Context(), appCtx)

			// THEN
			tc.assert(t, err, rs)
		})
	}
}
