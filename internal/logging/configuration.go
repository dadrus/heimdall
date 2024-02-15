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
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/x"
)

func NewLogger(conf config.LoggingConfig) zerolog.Logger {
	if conf.Format == config.LogTextFormat {
		return zerolog.New(zerolog.NewConsoleWriter(func(w *zerolog.ConsoleWriter) {
			w.TimeFormat = time.RFC3339
		})).Level(conf.Level).With().Timestamp().Logger()
	}

	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zerolog.TimestampFieldName = "timestamp"
	zerolog.LevelFieldName = "_level_name"
	zerolog.LevelFieldMarshalFunc = func(l zerolog.Level) string {
		return strings.ToUpper(l.String())
	}
	zerolog.MessageFieldName = "short_message"
	zerolog.ErrorFieldName = "_error" // nolint: reassign
	zerolog.CallerFieldName = "_caller"
	hostname, err := os.Hostname()

	return zerolog.New(os.Stdout).Level(conf.Level).With().
		Str("version", "1.1").
		Str("host", x.IfThenElse(err != nil, hostname, "unknown")).
		Timestamp().
		Logger().
		Hook(zerolog.HookFunc(func(e *zerolog.Event, level zerolog.Level, _ string) {
			if level != zerolog.NoLevel {
				e.Int8("level", int8(toSyslogLevel(level)))
			}
		}))
}
