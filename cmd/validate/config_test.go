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

package validate

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestValidateConfig(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc       string
		confFile string
		expError error
	}{
		{uc: "no config provided", expError: ErrNoConfigFile},
		{uc: "invalid config", confFile: "doesnotexist.yaml", expError: os.ErrNotExist},
		{uc: "valid config", confFile: "test_data/config.yaml"},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			cmd := NewValidateConfigCommand()
			cmd.Flags().StringP("config", "c", "", "Path to heimdall's configuration file.")

			if len(tc.confFile) != 0 {
				err := cmd.ParseFlags([]string{"--config", tc.confFile})
				require.NoError(t, err)
			}

			// WHEN
			err := validateConfig(cmd)

			// THEN
			if tc.expError != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.expError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestRunValidateConfigCommand(t *testing.T) {
	for _, tc := range []struct {
		uc       string
		confFile string
		expError string
	}{
		{uc: "invalid config", confFile: "doesnotexist.yaml", expError: "no such file or dir"},
		{uc: "valid config", confFile: "test_data/config.yaml"},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			exit, err := testsupport.PatchOSExit(t, func(int) {})
			require.NoError(t, err)

			cmd := NewValidateConfigCommand()

			buf := bytes.NewBuffer([]byte{})
			cmd.SetOut(buf)
			cmd.SetErr(buf)

			cmd.Flags().StringP("config", "c", "", "Path to heimdall's configuration file.")

			if len(tc.confFile) != 0 {
				err := cmd.ParseFlags([]string{"--config", tc.confFile})
				require.NoError(t, err)
			}

			// WHEN
			cmd.Run(cmd, []string{})

			log := buf.String()
			if len(tc.expError) != 0 {
				assert.Contains(t, log, tc.expError)
				assert.True(t, exit.Called)
				assert.Equal(t, 1, exit.Code)
			} else {
				assert.Contains(t, log, "Configuration is valid")
			}
		})
	}
}
