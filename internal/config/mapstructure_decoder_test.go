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
	"crypto/tls"
	"testing"

	"github.com/inhies/go-bytesize"
	"github.com/mitchellh/mapstructure"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestDecodeLogLevel(t *testing.T) {
	t.Parallel()

	type Type struct {
		Level zerolog.Level `mapstructure:"level"`
	}

	for _, tc := range []struct {
		config string
		expect zerolog.Level
	}{
		{config: `level: debug`, expect: zerolog.DebugLevel},
		{config: `level: info`, expect: zerolog.InfoLevel},
		{config: `level: warn`, expect: zerolog.WarnLevel},
		{config: `level: error`, expect: zerolog.ErrorLevel},
		{config: `level: fatal`, expect: zerolog.FatalLevel},
		{config: `level: panic`, expect: zerolog.PanicLevel},
		{config: `level: no`, expect: zerolog.NoLevel},
		{config: `level: disabled`, expect: zerolog.Disabled},
		{config: `level: trace`, expect: zerolog.TraceLevel},
	} {
		t.Run("case="+tc.config, func(t *testing.T) {
			// GIVEN
			var typ Type

			dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
				DecodeHook: logLevelDecodeHookFunc,
				Result:     &typ,
			})
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig([]byte(tc.config))
			require.NoError(t, err)

			// WHEN
			err = dec.Decode(conf)

			// THEN
			require.NoError(t, err)
			assert.Equal(t, tc.expect, typ.Level)
		})
	}
}

func TestDecodeLogFormat(t *testing.T) {
	t.Parallel()

	type Type struct {
		Format LogFormat `mapstructure:"format"`
	}

	for _, tc := range []struct {
		config string
		expect LogFormat
	}{
		{config: `format: gelf`, expect: LogGelfFormat},
		{config: `format: text`, expect: LogTextFormat},
		{config: `format: foo`, expect: LogTextFormat},
	} {
		t.Run("case="+tc.config, func(t *testing.T) {
			// GIVEN
			var typ Type

			dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
				DecodeHook: logFormatDecodeHookFunc,
				Result:     &typ,
			})
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig([]byte(tc.config))
			require.NoError(t, err)

			// WHEN
			err = dec.Decode(conf)

			// THEN
			require.NoError(t, err)
			assert.Equal(t, tc.expect, typ.Format)
		})
	}
}

func TestDecodeTLSCipherSuite(t *testing.T) {
	t.Parallel()

	type Type struct {
		CipherSuites TLSCipherSuites `mapstructure:"cipher_suites"`
	}

	for _, tc := range []struct {
		uc     string
		config []byte
		assert func(t *testing.T, err error, suites TLSCipherSuites)
	}{
		{
			uc: "unsupported cipher suite",
			config: []byte(`
cipher_suites:
- foo
`),
			assert: func(t *testing.T, err error, suites TLSCipherSuites) {
				t.Helper()

				require.Error(t, err)
				assert.Contains(t, err.Error(), "unsupported")
			},
		},
		{
			uc: "all supported cipher suites",
			config: []byte(`
cipher_suites:
- TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
- TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
- TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
- TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
- TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
- TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
`),
			assert: func(t *testing.T, err error, suites TLSCipherSuites) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, suites)
				require.Len(t, suites, 8)
				assert.ElementsMatch(t, suites, []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				})
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			var typ Type

			dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
				DecodeHook: DecodeTLSCipherSuiteHookFunc,
				Result:     &typ,
			})
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			// WHEN
			err = dec.Decode(conf)

			// THEN
			tc.assert(t, err, typ.CipherSuites)
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
				DecodeHook: DecodeTLSMinVersionHookFunc,
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

func TestStringToByteSizeHookFunc(t *testing.T) {
	t.Parallel()

	type Type struct {
		Size bytesize.ByteSize `mapstructure:"size"`
	}

	for _, tc := range []struct {
		config string
		expect bytesize.ByteSize
	}{
		{config: "size: 1B", expect: 1 * bytesize.B},
		{config: "size: 3KB", expect: 3 * bytesize.KB},
		{config: "size: 5MB", expect: 5 * bytesize.MB},
	} {
		t.Run("case="+tc.config, func(t *testing.T) {
			// GIVEN
			var typ Type

			dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
				DecodeHook: stringToByteSizeHookFunc(),
				Result:     &typ,
			})
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig([]byte(tc.config))
			require.NoError(t, err)

			// WHEN
			err = dec.Decode(conf)

			// THEN
			require.NoError(t, err)
			assert.Equal(t, tc.expect, typ.Size)
		})
	}
}
