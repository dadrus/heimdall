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

	for _, tc := range []struct {
		uc   string
		from zerolog.Level
		to   SyslogLevel
	}{
		{uc: "trace", from: zerolog.TraceLevel, to: Debugging},
		{uc: "debug", from: zerolog.DebugLevel, to: Debugging},
		{uc: "info", from: zerolog.InfoLevel, to: Informational},
		{uc: "warn", from: zerolog.WarnLevel, to: Warning},
		{uc: "error", from: zerolog.ErrorLevel, to: Error},
		{uc: "fatal", from: zerolog.FatalLevel, to: Critical},
		{uc: "panic", from: zerolog.PanicLevel, to: Alert},
		{uc: "everything else", from: zerolog.Level(10), to: Emergency},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// WHEN
			syslogLevel := toSyslogLevel(tc.from)

			// THEN
			assert.Equal(t, tc.to, syslogLevel)
		})
	}
}
