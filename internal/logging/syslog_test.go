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

package logging

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

func TestConvertLogLevelToSyslogLevel(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		from zerolog.Level
		to   SyslogLevel
	}{
		"trace":           {zerolog.TraceLevel, Debugging},
		"debug":           {zerolog.DebugLevel, Debugging},
		"info":            {zerolog.InfoLevel, Informational},
		"warn":            {zerolog.WarnLevel, Warning},
		"error":           {zerolog.ErrorLevel, Error},
		"fatal":           {zerolog.FatalLevel, Critical},
		"panic":           {zerolog.PanicLevel, Alert},
		"everything else": {zerolog.Level(10), Emergency},
	} {
		t.Run(uc, func(t *testing.T) {
			// WHEN
			syslogLevel := toSyslogLevel(tc.from)

			// THEN
			assert.Equal(t, tc.to, syslogLevel)
		})
	}
}
