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
	// nolint
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
