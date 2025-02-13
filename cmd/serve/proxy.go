// Copyright 2022-2025 Dimitrij Drus <dadrus@gmx.de>
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

package serve

import (
	"github.com/spf13/cobra"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/handler/proxy"
)

// NewProxyCommand represents the proxy command.
func NewProxyCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "proxy",
		Short:   "Starts heimdall in Reverse Proxy operation mode",
		Example: "heimdall serve proxy",
		RunE: func(cmd *cobra.Command, _ []string) error {
			app, err := createApp(
				cmd,
				fx.Options(
					proxy.Module,
					fx.Supply(config.ProxyMode),
				),
			)
			if err != nil {
				return err
			}

			app.Run()

			return nil
		},
	}
}
