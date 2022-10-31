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
	"github.com/dadrus/heimdall/internal/x"
)

func TestFetchRuleSets(t *testing.T) { //nolint:maintidx
	t.Parallel()

	bucketName := "new_bucket"
	backend := s3mem.New()
	s3 := gofakes3.New(backend)
	srv := httptest.NewServer(s3.Server())

	defer srv.Close()

	require.NoError(t, backend.CreateBucket(bucketName))

	for _, tc := range []struct {
		uc       string
		endpoint ruleSetEndpoint
		setup    func(t *testing.T)
		tearDown func(t *testing.T)
		assert   func(t *testing.T, err error, ruleSets []RuleSet)
	}{
		{
			uc: "failed to open bucket",
			endpoint: ruleSetEndpoint{
				URL: &url.URL{
					Scheme:   "s3",
					Host:     "foo",
					RawQuery: "endpoint=does-not-exist.local&foo=bar",
				},
			},
			assert: func(t *testing.T, err error, ruleSets []RuleSet) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "failed to open bucket")
			},
		},
		{
			uc: "iterate not existing bucket",
			endpoint: ruleSetEndpoint{
				URL: &url.URL{
					Scheme:   "s3",
					Host:     "foo",
					RawQuery: fmt.Sprintf("endpoint=%s&disableSSL=true&s3ForcePathStyle=true", srv.URL),
				},
			},
			assert: func(t *testing.T, err error, ruleSets []RuleSet) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "failed iterate blobs")
			},
		},
		{
			uc: "invalid rule set",
			endpoint: ruleSetEndpoint{
				URL: &url.URL{
					Scheme:   "s3",
					Host:     bucketName,
					RawQuery: fmt.Sprintf("endpoint=%s&disableSSL=true&s3ForcePathStyle=true", srv.URL),
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
			tearDown: func(t *testing.T) {
				t.Helper()

				_, err := backend.DeleteObject(bucketName, "test-rule")
				require.NoError(t, err)
			},
			assert: func(t *testing.T, err error, ruleSets []RuleSet) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "failed to decode")
			},
		},
		{
			uc: "empty bucket",
			endpoint: ruleSetEndpoint{
				URL: &url.URL{
					Scheme:   "s3",
					Host:     bucketName,
					RawQuery: fmt.Sprintf("endpoint=%s&disableSSL=true&s3ForcePathStyle=true", srv.URL),
				},
			},
			assert: func(t *testing.T, err error, ruleSets []RuleSet) {
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
					RawQuery: fmt.Sprintf("endpoint=%s&disableSSL=true&s3ForcePathStyle=true", srv.URL),
				},
				RulesPathPrefix: "foo/bar",
			},
			setup: func(t *testing.T) {
				t.Helper()

				data := `[{
					"id": "foobar",
					"url": "http://<**>/bar/foo/api",
					"methods": ["GET", "POST"],
					"execute": [
						{ "authenticator": "foobar" }
					]
				}]`

				_, err := backend.PutObject(bucketName, "test-rule",
					map[string]string{"Content-Type": "application/json"},
					strings.NewReader(data), int64(len(data)))
				require.NoError(t, err)
			},
			tearDown: func(t *testing.T) {
				t.Helper()

				_, err := backend.DeleteObject(bucketName, "test-rule")
				require.NoError(t, err)
			},
			assert: func(t *testing.T, err error, ruleSets []RuleSet) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "path prefix validation")
			},
		},
		{
			uc: "multiple valid rule sets in yaml and json formats",
			endpoint: ruleSetEndpoint{
				URL: &url.URL{
					Scheme:   "s3",
					Host:     bucketName,
					RawQuery: fmt.Sprintf("endpoint=%s&disableSSL=true&s3ForcePathStyle=true", srv.URL),
				},
				RulesPathPrefix: "foo/bar",
			},
			setup: func(t *testing.T) {
				t.Helper()

				ruleSet1 := `[
{
	"id": "foobar",
	"url": "http://<**>/foo/bar/api1",
	"methods": ["GET", "POST"],
	"execute": [
		{ "authenticator": "foobar" }
	]
}]`

				ruleSet2 := `
- id: barfoo
  url: http://<**>/foo/bar/api2
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
			tearDown: func(t *testing.T) {
				t.Helper()

				_, err := backend.DeleteObject(bucketName, "test-rule1")
				require.NoError(t, err)

				_, err = backend.DeleteObject(bucketName, "test-rule2")
				require.NoError(t, err)
			},
			assert: func(t *testing.T, err error, ruleSets []RuleSet) {
				t.Helper()

				require.NoError(t, err)

				require.Len(t, ruleSets, 2)

				assert.Contains(t, ruleSets[0].Key, "test-rule1")
				assert.NotEmpty(t, ruleSets[0].Hash)
				assert.Len(t, ruleSets[0].Rules, 1)
				assert.Equal(t, "foobar", ruleSets[0].Rules[0].ID)

				assert.Contains(t, ruleSets[1].Key, "test-rule2")
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
					RawQuery: fmt.Sprintf("endpoint=%s&disableSSL=true&s3ForcePathStyle=true", srv.URL),
				},
				Prefix: "api",
			},
			setup: func(t *testing.T) {
				t.Helper()

				ruleSet1 := `[
				{
					"id": "foobar",
					"url": "http://<**>/foo/bar/api1",
					"methods": ["GET", "POST"],
					"execute": [
						{ "authenticator": "foobar" }
					]
				}]`

				ruleSet2 := `[
				{
					"id": "barfoo",
					"url": "http://<**>/foo/bar/api2",
					"methods": ["GET", "POST"],
					"execute": [
						{ "authenticator": "barfoo" }
					]
				}]`

				_, err := backend.PutObject(bucketName, "api-rule",
					map[string]string{"Content-Type": "application/json"},
					strings.NewReader(ruleSet1), int64(len(ruleSet1)))
				require.NoError(t, err)

				_, err = backend.PutObject(bucketName, "test-rule",
					map[string]string{"Content-Type": "application/json"},
					strings.NewReader(ruleSet2), int64(len(ruleSet2)))
				require.NoError(t, err)
			},
			tearDown: func(t *testing.T) {
				t.Helper()

				_, err := backend.DeleteObject(bucketName, "api-rule")
				require.NoError(t, err)

				_, err = backend.DeleteObject(bucketName, "test-rule")
				require.NoError(t, err)
			},
			assert: func(t *testing.T, err error, ruleSets []RuleSet) {
				t.Helper()

				require.NoError(t, err)

				require.Len(t, ruleSets, 1)

				assert.Contains(t, ruleSets[0].Key, "api-rule")
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
					RawQuery: fmt.Sprintf("endpoint=%s&disableSSL=true&s3ForcePathStyle=true", srv.URL),
				},
				Prefix: "api",
			},
			assert: func(t *testing.T, err error, ruleSets []RuleSet) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "attributes")
			},
		},
		{
			uc: "existing rule set specified in the path",
			endpoint: ruleSetEndpoint{
				URL: &url.URL{
					Scheme:   "s3",
					Host:     bucketName,
					Path:     "ruleset",
					RawQuery: fmt.Sprintf("endpoint=%s&disableSSL=true&s3ForcePathStyle=true", srv.URL),
				},
				Prefix: "api",
			},
			setup: func(t *testing.T) {
				t.Helper()

				ruleSet1 := `[
				{
					"id": "foobar",
					"url": "http://<**>/foo/bar/api1",
					"methods": ["GET", "POST"],
					"execute": [
						{ "authenticator": "foobar" }
					]
				}]`

				_, err := backend.PutObject(bucketName, "ruleset",
					map[string]string{"Content-Type": "application/json"},
					strings.NewReader(ruleSet1), int64(len(ruleSet1)))
				require.NoError(t, err)
			},
			tearDown: func(t *testing.T) {
				t.Helper()

				_, err := backend.DeleteObject(bucketName, "ruleset")
				require.NoError(t, err)
			},
			assert: func(t *testing.T, err error, ruleSets []RuleSet) {
				t.Helper()

				require.NoError(t, err)

				require.Len(t, ruleSets, 1)

				assert.Contains(t, ruleSets[0].Key, "ruleset")
				assert.NotEmpty(t, ruleSets[0].Hash)
				assert.Len(t, ruleSets[0].Rules, 1)
				assert.Equal(t, "foobar", ruleSets[0].Rules[0].ID)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			setup := x.IfThenElse(tc.setup != nil, tc.setup, func(t *testing.T) { t.Helper() })
			tearDown := x.IfThenElse(tc.tearDown != nil, tc.tearDown, func(t *testing.T) { t.Helper() })

			setup(t)
			defer tearDown(t)

			// WHEN
			rs, err := tc.endpoint.FetchRuleSets(context.Background())

			// THEN
			tc.assert(t, err, rs)
		})
	}
}
