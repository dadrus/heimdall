package validate

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestValidateRuleset(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc        string
		confFile  string
		rulesFile string
		expError  error
	}{
		{
			uc:       "no config provided",
			expError: ErrNoConfigFile,
		},
		{
			uc:       "invalid configconfig file",
			confFile: "doesnotexist.yaml",
			expError: os.ErrNotExist,
		},
		{
			uc:        "invalid rule set file",
			confFile:  "test_data/config.yaml",
			rulesFile: "doesnotexist.yaml",
			expError:  os.ErrNotExist,
		},
		{
			uc:        "everything is valid",
			confFile:  "test_data/config.yaml",
			rulesFile: "test_data/ruleset.yaml",
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			cmd := NewValidateRulesCommand()
			cmd.Flags().StringP("config", "c", "", "Path to heimdall's configuration file.")

			if len(tc.confFile) != 0 {
				err := cmd.ParseFlags([]string{"--config", tc.confFile})
				require.NoError(t, err)
			}

			// WHEN
			err := validateRuleSet(cmd, []string{tc.rulesFile})

			// THEN
			if tc.expError != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.expError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestRunValidateRulesCommand(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc        string
		confFile  string
		rulesFile string
		expError  string
	}{
		{
			uc:       "validation fails",
			expError: "no config file",
		},
		{
			uc:        "everything is valid",
			confFile:  "test_data/config.yaml",
			rulesFile: "test_data/ruleset.yaml",
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			exit, err := testsupport.PatchOSExit(t, func(int) {})
			require.NoError(t, err)

			cmd := NewValidateRulesCommand()

			buf := bytes.NewBuffer([]byte{})
			cmd.SetOut(buf)
			cmd.SetErr(buf)

			cmd.Flags().StringP("config", "c", "", "Path to heimdall's configuration file.")

			if len(tc.confFile) != 0 {
				err := cmd.ParseFlags([]string{"--config", tc.confFile})
				require.NoError(t, err)
			}

			// WHEN
			cmd.Run(cmd, []string{tc.rulesFile})

			log := buf.String()
			if len(tc.expError) != 0 {
				assert.Contains(t, log, tc.expError)
				assert.True(t, exit.Called)
				assert.Equal(t, 1, exit.Code)
			} else {
				assert.Contains(t, log, "Rule set is valid")
			}
		})
	}
}
