package config

import (
	"crypto/tls"
	"reflect"

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
func decodeTLSCipherSuiteHookFunc(from reflect.Type, to reflect.Type, data any) (any, error) {
	var suites TLSCipherSuites

	if from.Kind() != reflect.Slice {
		return data, nil
	}

	dect := reflect.ValueOf(&suites).Elem().Type()
	if !dect.AssignableTo(to) {
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

func decodeTLSMinVersionHookFunc(from reflect.Type, to reflect.Type, data any) (any, error) {
	var minVersion TLSMinVersion

	if from.Kind() != reflect.String {
		return data, nil
	}

	dect := reflect.ValueOf(&minVersion).Elem().Type()
	if !dect.AssignableTo(to) {
		return data, nil
	}

	switch data {
	case "TLS1.2":
		return tls.VersionTLS12, nil
	case "TLS1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, errorchain.NewWithMessagef(heimdall.ErrConfiguration, "TLS version %s is unsupported", data)
	}
}
