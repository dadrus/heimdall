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
	"os"

	"github.com/spf13/cobra"

	"github.com/dadrus/heimdall/cmd/flags"
	"github.com/dadrus/heimdall/internal/config"
)

// NewValidateConfigCommand represents the "validate config" command.
func NewValidateConfigCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "config",
		Short:   "Validates heimdall's configuration",
		Example: "heimdall validate config -c myconfig.yaml",
		Run: func(cmd *cobra.Command, _ []string) {
			if err := validateConfig(cmd); err != nil {
				cmd.PrintErrf("%v\n", err)

				os.Exit(1)
			}

			cmd.Println("Configuration is valid")
		},
	}
}

func validateConfig(cmd *cobra.Command) error {
	configPath, _ := cmd.Flags().GetString(flags.Config)
	if len(configPath) == 0 {
		return ErrNoConfigFile
	}

	return config.ValidateConfig(configPath)
}
