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
	"errors"

	"github.com/spf13/cobra"

	"github.com/dadrus/heimdall/internal/config"
)

var ErrNoConfigFile = errors.New("no config file provided")

// NewValidateConfigCommand represents the "validate config" command.
func NewValidateConfigCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "config",
		Short: "Validates heimdall's configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			configPath, _ := cmd.Flags().GetString("config")
			if len(configPath) == 0 {
				return ErrNoConfigFile
			}

			if err := config.ValidateConfig(configPath); err != nil {
				cmd.PrintErrf("%v\n", err)
			} else {
				cmd.Printf("Configuration is valid\n")
			}

			return nil
		},
	}
}
