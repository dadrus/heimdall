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
	"net/url"
	"strings"
	"testing"

	"github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3mem"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/config"
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

	for _, tc := range []struct {
		uc       string
		endpoint ruleSetEndpoint
		setup    func(t *testing.T)
		assert   func(t *testing.T, err error, ruleSets []*config.RuleSet)
	}{
		{
			uc: "failed to open bucket",
			endpoint: ruleSetEndpoint{
				URL: &url.URL{
					Scheme:   "s3",
					Host:     "foo",
					RawQuery: "endpoint=does-not-exist.local&foo=bar&region=eu-central-1",
				},
			},
			assert: func(t *testing.T, err error, ruleSets []*config.RuleSet) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "failed to open bucket")
			},
		},
		{
			uc: "iterate not existing bucket",
			endpoint: ruleSetEndpoint{
				URL: &url.URL{
					Scheme:   "s3",
					Host:     "foo",
					RawQuery: fmt.Sprintf("endpoint=%s&disableSSL=true&s3ForcePathStyle=true&region=eu-central-1", srv.URL),
				},
			},
			assert: func(t *testing.T, err error, ruleSets []*config.RuleSet) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "failed iterate blobs")
			},
		},
		{
			uc: "invalid rule set",
			endpoint: ruleSetEndpoint{
				URL: &url.URL{
					Scheme:   "s3",
					Host:     bucketName,
					RawQuery: fmt.Sprintf("endpoint=%s&disableSSL=true&s3ForcePathStyle=true&region=eu-central-1", srv.URL),
				},
			},
			setup: func(t *testing.T) {
				t.Helper()

				data := `{"test":"foo"}`

				_, err := backend.PutObject(bucketName, "test-rule",
					map[string]string{"Content-Type": "application/json"},
					strings.NewReader(data), int64(len(data)))
				require.NoError(t, err)
			},
			assert: func(t *testing.T, err error, ruleSets []*config.RuleSet) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "failed to decode")
			},
		},
		{
			uc: "empty bucket",
			endpoint: ruleSetEndpoint{
				URL: &url.URL{
					Scheme:   "s3",
					Host:     bucketName,
					RawQuery: fmt.Sprintf("endpoint=%s&disableSSL=true&s3ForcePathStyle=true&region=eu-central-1", srv.URL),
				},
			},
			assert: func(t *testing.T, err error, ruleSets []*config.RuleSet) {
				t.Helper()

				require.NoError(t, err)
				require.Empty(t, ruleSets)
			},
		},
		{
			uc: "bucket with an empty blob",
			endpoint: ruleSetEndpoint{
				URL: &url.URL{
					Scheme:   "s3",
					Host:     bucketName,
					RawQuery: fmt.Sprintf("endpoint=%s&disableSSL=true&s3ForcePathStyle=true&region=eu-central-1", srv.URL),
				},
			},
			setup: func(t *testing.T) {
				t.Helper()

				_, err := backend.PutObject(bucketName, "test-rule",
					map[string]string{"Content-Type": "application/json"},
					strings.NewReader(""), 0)
				require.NoError(t, err)
			},
			assert: func(t *testing.T, err error, ruleSets []*config.RuleSet) {
				t.Helper()

				require.NoError(t, err)
				require.Empty(t, ruleSets)
			},
		},
		{
			uc: "rule set with path prefix validation error",
			endpoint: ruleSetEndpoint{
				URL: &url.URL{
					Scheme:   "s3",
					Host:     bucketName,
					RawQuery: fmt.Sprintf("endpoint=%s&disableSSL=true&s3ForcePathStyle=true&region=eu-central-1", srv.URL),
				},
				RulesPathPrefix: "foo/bar",
			},
			setup: func(t *testing.T) {
				t.Helper()

				data := `
{
	"version": "1",
	"name": "test",
	"rules": [{
		"id": "foobar",
		"match": "http://<**>/bar/foo/api",
		"methods": ["GET", "POST"],
		"execute": [
			{ "authenticator": "foobar" }
		]
	}]
}`

				_, err := backend.PutObject(bucketName, "test-rule",
					map[string]string{"Content-Type": "application/json"},
					strings.NewReader(data), int64(len(data)))
				require.NoError(t, err)
			},
			assert: func(t *testing.T, err error, ruleSets []*config.RuleSet) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "path prefix validation")
			},
		},
		{
			uc: "multiple valid rule sets in yaml and json formats",
			endpoint: ruleSetEndpoint{
				URL: &url.URL{
					Scheme:   "s3",
					Host:     bucketName,
					RawQuery: fmt.Sprintf("endpoint=%s&disableSSL=true&s3ForcePathStyle=true&region=eu-central-1", srv.URL),
				},
				RulesPathPrefix: "foo/bar",
			},
			setup: func(t *testing.T) {
				t.Helper()

				ruleSet1 := `
{
	"version": "1",
	"name": "test",
	"rules": [{
		"id": "foobar",
		"match": "http://<**>/foo/bar/api1",
		"methods": ["GET", "POST"],
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
  match: http://<**>/foo/bar/api2
  methods: 
  - GET
  - POST
  execute:
  - authenticator: barfoo`

				_, err := backend.PutObject(bucketName, "test-rule1",
					map[string]string{"Content-Type": "application/json"},
					strings.NewReader(ruleSet1), int64(len(ruleSet1)))
				require.NoError(t, err)

				_, err = backend.PutObject(bucketName, "test-rule2",
					map[string]string{"Content-Type": "application/yaml"},
					strings.NewReader(ruleSet2), int64(len(ruleSet2)))
				require.NoError(t, err)
			},
			assert: func(t *testing.T, err error, ruleSets []*config.RuleSet) {
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
		{
			uc: "only one rule set adhering to the required prefix",
			endpoint: ruleSetEndpoint{
				URL: &url.URL{
					Scheme:   "s3",
					Host:     bucketName,
					RawQuery: fmt.Sprintf("endpoint=%s&disableSSL=true&s3ForcePathStyle=true&region=eu-central-1", srv.URL),
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
					"match": "http://<**>/foo/bar/api1",
					"methods": ["GET", "POST"],
					"execute": [
						{ "authenticator": "foobar" }
					]
				}]}`

				ruleSet2 := `{
				"version": "1",
				"name": "test2",
				"rules": [{
					"id": "barfoo",
					"url": "http://<**>/foo/bar/api2",
					"methods": ["GET", "POST"],
					"execute": [
						{ "authenticator": "barfoo" }
					]
				}]}`

				_, err := backend.PutObject(bucketName, "api-rule",
					map[string]string{"Content-Type": "application/json"},
					strings.NewReader(ruleSet1), int64(len(ruleSet1)))
				require.NoError(t, err)

				_, err = backend.PutObject(bucketName, "test-rule",
					map[string]string{"Content-Type": "application/json"},
					strings.NewReader(ruleSet2), int64(len(ruleSet2)))
				require.NoError(t, err)
			},
			assert: func(t *testing.T, err error, ruleSets []*config.RuleSet) {
				t.Helper()

				require.NoError(t, err)

				require.Len(t, ruleSets, 1)

				assert.Contains(t, ruleSets[0].Source, "api-rule")
				assert.NotEmpty(t, ruleSets[0].Hash)
				assert.Len(t, ruleSets[0].Rules, 1)
				assert.Equal(t, "foobar", ruleSets[0].Rules[0].ID)
			},
		},
		{
			uc: "not existing rule set specified in the path",
			endpoint: ruleSetEndpoint{
				URL: &url.URL{
					Scheme:   "s3",
					Host:     bucketName,
					Path:     "ruleset",
					RawQuery: fmt.Sprintf("endpoint=%s&disableSSL=true&s3ForcePathStyle=true&region=eu-central-1", srv.URL),
				},
				Prefix: "api",
			},
			assert: func(t *testing.T, err error, ruleSets []*config.RuleSet) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "attributes")
			},
		},
		{
			uc: "empty blob specified in the path",
			endpoint: ruleSetEndpoint{
				URL: &url.URL{
					Scheme:   "s3",
					Host:     bucketName,
					Path:     "ruleset",
					RawQuery: fmt.Sprintf("endpoint=%s&disableSSL=true&s3ForcePathStyle=true&region=eu-central-1", srv.URL),
				},
				Prefix: "api",
			},
			setup: func(t *testing.T) {
				t.Helper()

				_, err := backend.PutObject(bucketName, "ruleset",
					map[string]string{"Content-Type": "application/json"},
					strings.NewReader(""), 0)
				require.NoError(t, err)
			},
			assert: func(t *testing.T, err error, ruleSets []*config.RuleSet) {
				t.Helper()

				require.NoError(t, err)
				assert.Empty(t, ruleSets)
			},
		},
		{
			uc: "existing rule set specified in the path",
			endpoint: ruleSetEndpoint{
				URL: &url.URL{
					Scheme:   "s3",
					Host:     bucketName,
					Path:     "ruleset",
					RawQuery: fmt.Sprintf("endpoint=%s&disableSSL=true&s3ForcePathStyle=true&region=eu-central-1", srv.URL),
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
					"match": "http://<**>/foo/bar/api1",
					"methods": ["GET", "POST"],
					"execute": [
						{ "authenticator": "foobar" }
					]
				}]}`

				_, err := backend.PutObject(bucketName, "ruleset",
					map[string]string{"Content-Type": "application/json"},
					strings.NewReader(ruleSet1), int64(len(ruleSet1)))
				require.NoError(t, err)
			},
			assert: func(t *testing.T, err error, ruleSets []*config.RuleSet) {
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
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			clearBucket(t)

			setup := x.IfThenElse(tc.setup != nil, tc.setup, func(t *testing.T) { t.Helper() })
			setup(t)

			// WHEN
			rs, err := tc.endpoint.FetchRuleSets(context.Background())

			// THEN
			tc.assert(t, err, rs)
		})
	}
}
