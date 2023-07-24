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

import "github.com/rs/zerolog"

// SyslogLevel defines syslog log levels.
type SyslogLevel int8

const (
	Emergency SyslogLevel = iota
	Alert
	Critical
	Error
	Warning
	Notice
	Informational
	Debugging
)

func toSyslogLevel(level zerolog.Level) SyslogLevel {
	switch level {
	case zerolog.DebugLevel, zerolog.TraceLevel:
		return Debugging
	case zerolog.InfoLevel:
		return Informational
	case zerolog.WarnLevel:
		return Warning
	case zerolog.ErrorLevel:
		return Error
	case zerolog.FatalLevel:
		return Critical
	case zerolog.PanicLevel:
		return Alert
	default:
		return Emergency
	}
}
