package config

import (
	"crypto/tls"
	"testing"

	"github.com/mitchellh/mapstructure"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/testsupport"
)

func TestDecodeLogLevel(t *testing.T) {
	t.Parallel()

	type Type struct {
		Level zerolog.Level `mapstructure:"level"`
	}

	for _, tc := range []struct {
		uc     string
		config []byte
		assert func(t *testing.T, err error, level zerolog.Level)
	}{
		{
			uc:     "debug level",
			config: []byte(`level: debug`),
			assert: func(t *testing.T, err error, level zerolog.Level) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, zerolog.DebugLevel, level)
			},
		},
		{
			uc:     "info level",
			config: []byte(`level: info`),
			assert: func(t *testing.T, err error, level zerolog.Level) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, zerolog.InfoLevel, level)
			},
		},
		{
			uc:     "warn level",
			config: []byte(`level: warn`),
			assert: func(t *testing.T, err error, level zerolog.Level) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, zerolog.WarnLevel, level)
			},
		},
		{
			uc:     "error level",
			config: []byte(`level: error`),
			assert: func(t *testing.T, err error, level zerolog.Level) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, zerolog.ErrorLevel, level)
			},
		},
		{
			uc:     "fatal level",
			config: []byte(`level: fatal`),
			assert: func(t *testing.T, err error, level zerolog.Level) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, zerolog.FatalLevel, level)
			},
		},
		{
			uc:     "panic level",
			config: []byte(`level: panic`),
			assert: func(t *testing.T, err error, level zerolog.Level) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, zerolog.PanicLevel, level)
			},
		},
		{
			uc:     "no level",
			config: []byte(`level: no`),
			assert: func(t *testing.T, err error, level zerolog.Level) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, zerolog.NoLevel, level)
			},
		},
		{
			uc:     "disabled",
			config: []byte(`level: disabled`),
			assert: func(t *testing.T, err error, level zerolog.Level) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, zerolog.Disabled, level)
			},
		},
		{
			uc:     "trace level",
			config: []byte(`level: trace`),
			assert: func(t *testing.T, err error, level zerolog.Level) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, zerolog.TraceLevel, level)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			var typ Type

			dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
				DecodeHook: logLevelDecodeHookFunc,
				Result:     &typ,
			})
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			// WHEN
			err = dec.Decode(conf)

			// THEN
			tc.assert(t, err, typ.Level)
		})
	}
}

func TestDecodeLogFormat(t *testing.T) {
	t.Parallel()

	type Type struct {
		Format LogFormat `mapstructure:"format"`
	}

	for _, tc := range []struct {
		uc     string
		config []byte
		assert func(t *testing.T, err error, format LogFormat)
	}{
		{
			uc:     "gelf format",
			config: []byte(`format: gelf`),
			assert: func(t *testing.T, err error, format LogFormat) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, LogGelfFormat, format)
			},
		},
		{
			uc:     "text format",
			config: []byte(`format: text`),
			assert: func(t *testing.T, err error, format LogFormat) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, LogTextFormat, format)
			},
		},
		{
			uc:     "unknown format with text as fallback",
			config: []byte(`format: foo`),
			assert: func(t *testing.T, err error, format LogFormat) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, LogTextFormat, format)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			var typ Type

			dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
				DecodeHook: logFormatDecodeHookFunc,
				Result:     &typ,
			})
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			// WHEN
			err = dec.Decode(conf)

			// THEN
			tc.assert(t, err, typ.Format)
		})
	}
}

func TestDecodeTLSMinVersion(t *testing.T) {
	t.Parallel()

	type Type struct {
		MinVersion TLSMinVersion `mapstructure:"min_version"`
	}

	for _, tc := range []struct {
		uc     string
		config []byte
		assert func(t *testing.T, err error, minVersion TLSMinVersion)
	}{
		{
			uc:     "unsupported version",
			config: []byte(`min_version: foo`),
			assert: func(t *testing.T, err error, minVersion TLSMinVersion) {
				t.Helper()

				require.Error(t, err)
				assert.Contains(t, err.Error(), "unsupported")
			},
		},
		{
			uc:     "TLS v1.2 version",
			config: []byte(`min_version: TLS1.2`),
			assert: func(t *testing.T, err error, minVersion TLSMinVersion) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, TLSMinVersion(tls.VersionTLS12), minVersion)
			},
		},
		{
			uc:     "TLS v1.3 version",
			config: []byte(`min_version: TLS1.3`),
			assert: func(t *testing.T, err error, minVersion TLSMinVersion) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, TLSMinVersion(tls.VersionTLS13), minVersion)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			var typ Type

			dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
				DecodeHook: decodeTLSMinVersionHookFunc,
				Result:     &typ,
			})
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			// WHEN
			err = dec.Decode(conf)

			// THEN
			tc.assert(t, err, typ.MinVersion)
		})
	}
}
