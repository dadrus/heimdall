package convert

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConvertRuleSet(t *testing.T) {
	t.Parallel()

	testDir := t.TempDir()

	for uc, tc := range map[string]struct {
		args   func(t *testing.T) []string
		assert func(t *testing.T, err error, result string)
	}{
		"no options set": {
			args: func(t *testing.T) []string {
				t.Helper()

				return []string{"/foo/bar"}
			},
			assert: func(t *testing.T, err error, _ string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, `"desired-version" not set`)
			},
		},
		"mandatory flags set, but no ruleset path": {
			args: func(t *testing.T) []string {
				t.Helper()

				return []string{"--" + convertRuleSetFlagDesiredVersion, "1beta1"}
			},
			assert: func(t *testing.T, err error, _ string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, `accepts 1 arg(s), received 0`)
			},
		},
		"provided ruleset file does not exist": {
			args: func(t *testing.T) []string {
				t.Helper()

				return []string{"--" + convertRuleSetFlagDesiredVersion, "1beta1", "/does/not/exist"}
			},
			assert: func(t *testing.T, err error, _ string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "no such file")
			},
		},
		"conversion failed": {
			args: func(t *testing.T) []string {
				t.Helper()

				rulesetFile := filepath.Join(t.TempDir(), "ruleset.yaml")

				err := os.WriteFile(rulesetFile, []byte("foo: bar"), 0o600)
				require.NoError(t, err)

				return []string{"--" + convertRuleSetFlagDesiredVersion, "1beta1", rulesetFile}
			},
			assert: func(t *testing.T, err error, _ string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "unexpected source ruleset version")
			},
		},
		"yaml ruleset successfully converted and printed to stdout": {
			args: func(t *testing.T) []string {
				t.Helper()

				rulesetFile := filepath.Join(testDir, "ruleset1.yaml")

				err := os.WriteFile(rulesetFile, []byte(`
version: "1alpha4"
name: test-rule-set
rules:
- id: rule:foo
  match:
    routes:
      - path: /**
    backtracking_enabled: true
    scheme: http
    hosts:
      - type: glob
        value: foo.bar
    methods: [GET, POST]
  forward_to:
    host: bar.foo
    rewrite:
      strip_path_prefix: /foo
      add_path_prefix: /baz
      strip_query_parameters: [boo]
  execute:
    - authenticator: jwt_authenticator1
    - authorizer: allow_all_authorizer
    - finalizer: jwt
      config:
        claims: |
          {"foo": "bar"}
`), 0o600)
				require.NoError(t, err)

				return []string{"--" + convertRuleSetFlagDesiredVersion, "1beta1", rulesetFile}
			},
			assert: func(t *testing.T, err error, result string) {
				t.Helper()

				require.NoError(t, err)

				assert.Contains(t, result, "version: 1beta1")
			},
		},
		"json ruleset successfully converted and printed to stdout": {
			args: func(t *testing.T) []string {
				t.Helper()

				rulesetFile := filepath.Join(testDir, "ruleset1.json")

				err := os.WriteFile(rulesetFile, []byte(`{
"version": "1alpha4",
"name": "test-rule-set",
"rules": [
  {
    "id": "rule:foo",
    "match": {
      "routes": [
        { "path": "/**" }
      ],
      "backtracking_enabled": true,
      "scheme": "http",
      "hosts": [
        { "type": "glob", "value": "foo.bar" } 
      ],
      "methods": ["GET", "POST"]
    },
    "forward_to": {
      "host": "bar.foo",
      "rewrite": {
        "strip_path_prefix": "/foo",
        "add_path_prefix": "/baz",
        "strip_query_parameters": ["boo"]
      }
    },
    "execute": [
      { "authenticator": "jwt_authenticator1" },
      { "authorizer": "allow_all_authorizer" },
      { 
        "finalizer": "jwt",
        "config": {
          "claims": "{\"foo\": \"bar\"}"
        }
      }
    ]
  }
]
}
`), 0o600)
				require.NoError(t, err)

				return []string{"--" + convertRuleSetFlagDesiredVersion, "1beta1", rulesetFile}
			},
			assert: func(t *testing.T, err error, result string) {
				t.Helper()

				require.NoError(t, err)

				assert.Contains(t, result, "1beta1")
			},
		},
		"ruleset successfully converted and written to a file": {
			args: func(t *testing.T) []string {
				t.Helper()

				inputFile := filepath.Join(testDir, "ruleset2.yaml")
				outputFile := filepath.Join(testDir, "converted.yaml")

				err := os.WriteFile(inputFile, []byte(`
version: "1alpha4"
name: test-rule-set
rules:
- id: rule:foo
  match:
    routes:
      - path: /**
    backtracking_enabled: true
    scheme: http
    hosts:
      - type: glob
        value: foo.bar
    methods: [GET, POST]
  forward_to:
    host: bar.foo
    rewrite:
      strip_path_prefix: /foo
      add_path_prefix: /baz
      strip_query_parameters: [boo]
  execute:
    - authenticator: jwt_authenticator1
    - authorizer: allow_all_authorizer
    - finalizer: jwt
      config:
        claims: |
          {"foo": "bar"}
`), 0o600)
				require.NoError(t, err)

				return []string{
					"--" + convertRuleSetFlagDesiredVersion, "1beta1",
					"--" + convertRuleSetFlagOutputFile, outputFile,
					inputFile,
				}
			},
			assert: func(t *testing.T, err error, _ string) {
				t.Helper()

				require.NoError(t, err)

				outputFile, err := os.Open(filepath.Join(testDir, "converted.yaml"))
				require.NoError(t, err)

				res, err := io.ReadAll(outputFile)
				require.NoError(t, err)

				assert.Contains(t, string(res), "version: 1beta1")
			},
		},
		"ruleset successfully converted, but writing to the output file failed": {
			args: func(t *testing.T) []string {
				t.Helper()

				inputFile := filepath.Join(testDir, "ruleset2.yaml")
				outputFile := filepath.Join(testDir, "converted2.yaml")
				file, err := os.Create(outputFile)
				require.NoError(t, err)

				err = file.Chmod(0o400)
				require.NoError(t, err)

				_ = file.Close()

				err = os.WriteFile(inputFile, []byte(`
version: "1alpha4"
name: test-rule-set
rules:
- id: rule:foo
  match:
    routes:
      - path: /**
    backtracking_enabled: true
    scheme: http
    hosts:
      - type: glob
        value: foo.bar
    methods: [GET, POST]
  forward_to:
    host: bar.foo
    rewrite:
      strip_path_prefix: /foo
      add_path_prefix: /baz
      strip_query_parameters: [boo]
  execute:
    - authenticator: jwt_authenticator1
    - authorizer: allow_all_authorizer
    - finalizer: jwt
      config:
        claims: |
          {"foo": "bar"}
`), 0o600)
				require.NoError(t, err)

				return []string{
					"--" + convertRuleSetFlagDesiredVersion, "1beta1",
					"--" + convertRuleSetFlagOutputFile, outputFile,
					inputFile,
				}
			},
			assert: func(t *testing.T, err error, _ string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "permission denied")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			cmd := NewConvertRulesCommand()
			cmd.SetArgs(tc.args(t))

			// Capture stdout
			var out bytes.Buffer
			cmd.SetOut(&out)

			// WHEN
			err := cmd.Execute()

			// THEN
			tc.assert(t, err, out.String())
		})
	}
}
