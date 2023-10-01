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

package config

import (
	"fmt"
	"os"
)

type MetricsConfig struct {
	Enabled bool `koanf:"enabled"`
}

func envOr(key, defaultValue string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}

	return defaultValue
}

func (c MetricsConfig) Address() string {
	return fmt.Sprintf("%s:%s",
		envOr("OTEL_EXPORTER_PROMETHEUS_HOST", "127.0.0.1"),
		envOr("OTEL_EXPORTER_PROMETHEUS_PORT", "9464"),
	)
}
