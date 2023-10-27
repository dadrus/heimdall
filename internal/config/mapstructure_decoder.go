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
	"reflect"

	"github.com/inhies/go-bytesize"
	"github.com/mitchellh/mapstructure"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// Decode zeroLog LogLevels from strings.
// nolint: cyclop
func logLevelDecodeHookFunc(from reflect.Type, to reflect.Type, data any) (any, error) {
	if from.Kind() != reflect.String {
		return data, nil
	}

	if to != reflect.TypeOf(zerolog.Level(0)) {
		return data, nil
	}

	switch data {
	case "panic":
		return zerolog.PanicLevel, nil
	case "fatal":
		return zerolog.FatalLevel, nil
	case "error":
		return zerolog.ErrorLevel, nil
	case "warn":
		return zerolog.WarnLevel, nil
	case "debug":
		return zerolog.DebugLevel, nil
	case "trace":
		return zerolog.TraceLevel, nil
	case "no":
		return zerolog.NoLevel, nil
	case "disabled":
		return zerolog.Disabled, nil
	case "info":
		return zerolog.InfoLevel, nil
	default:
		return zerolog.InfoLevel, nil
	}
}

func logFormatDecodeHookFunc(from reflect.Type, to reflect.Type, val any) (any, error) {
	if from.Kind() == reflect.String && to.Name() == "LogFormat" {
		return x.IfThenElse(val == "gelf", LogGelfFormat, LogTextFormat), nil
	}

	return val, nil
}

//nolint:cyclop
func DecodeTLSCipherSuiteHookFunc(from reflect.Type, to reflect.Type, data any) (any, error) {
	var suites TLSCipherSuites

	if from.Kind() != reflect.Slice || to != reflect.TypeOf(TLSCipherSuites{}) {
		return data, nil
	}

	// nolint: forcetypeassert
	// already checked above
	for _, val := range data.([]any) {
		var alg uint16

		switch val {
		case "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256":
			alg = tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
		case "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":
			alg = tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
		case "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":
			alg = tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
		case "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":
			alg = tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
		case "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":
			alg = tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
		case "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":
			alg = tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
		case "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256":
			alg = tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
		case "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256":
			alg = tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
		default:
			return 0, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
				"TLS cipher suite %s is unsupported", val)
		}

		suites = append(suites, alg)
	}

	return suites, nil
}

func DecodeTLSMinVersionHookFunc(from reflect.Type, to reflect.Type, data any) (any, error) {
	if from.Kind() != reflect.String || to != reflect.TypeOf(TLSMinVersion(0)) {
		return data, nil
	}

	switch data {
	case "TLS1.2":
		return tls.VersionTLS12, nil
	case "TLS1.3":
		return tls.VersionTLS13, nil
	default:
		return data, errorchain.NewWithMessagef(heimdall.ErrConfiguration, "TLS version %s is unsupported", data)
	}
}

func stringToByteSizeHookFunc() mapstructure.DecodeHookFunc {
	return func(f reflect.Type, t reflect.Type, data interface{}) (interface{}, error) {
		if f.Kind() != reflect.String {
			return data, nil
		}

		if t != reflect.TypeOf(bytesize.ByteSize(0)) {
			return data, nil
		}

		// Convert it by parsing
		// nolint: forcetypeassert
		return bytesize.Parse(data.(string))
	}
}
