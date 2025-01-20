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

package cmd

import (
	"github.com/spf13/cobra"

	"github.com/dadrus/heimdall/cmd/flags"
	"github.com/dadrus/heimdall/cmd/serve"
)

// nolint: gochecknoinits
func init() {
	RootCmd.AddCommand(newServeCmd())
}

func newServeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Starts the heimdall in one of its operations modes (decision or proxy)",
	}

	flags.RegisterGlobalFlags(cmd)

	cmd.AddCommand(serve.NewProxyCommand())
	cmd.AddCommand(serve.NewDecisionCommand())

	return cmd
}
