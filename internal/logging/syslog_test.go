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
