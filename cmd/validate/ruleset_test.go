package validate

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			cmd := NewValidateRuleSetCommand()
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
