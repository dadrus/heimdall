// Copyright 2026 Dimitrij Drus <dadrus@gmx.de>
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

package httpx

import (
	"errors"
	"strings"

	"github.com/dadrus/heimdall/internal/x/stringx"
)

var (
	ErrInvalidForwardedIP = errors.New("invalid forwarded ip")
	errObfuscatedIP       = errors.New("obfuscated ip")
)

func IPsFromXForwardedFor(dst []string, values []string) ([]string, error) {
	for _, value := range values {
		start := 0

		for i := 0; i <= len(value); i++ {
			if i != len(value) && value[i] != ',' {
				continue
			}

			token := strings.TrimSpace(value[start:i])
			if len(token) != 0 {
				if !isIP(token) {
					return dst, ErrInvalidForwardedIP
				}

				dst = append(dst, token)
			}

			start = i + 1
		}
	}

	return dst, nil
}

//nolint:cyclop
func IPsFromForwarded(dst []string, values []string) ([]string, error) {
	for _, value := range values {
		paramStart := 0
		quoted := false
		escaped := false

		for i := 0; i <= len(value); i++ {
			if i == len(value) || (!quoted && (value[i] == ',' || value[i] == ';')) {
				var err error

				dst, err = appendIPFromForwardedParam(dst, value[paramStart:i])
				if err != nil {
					return nil, err
				}

				paramStart = i + 1

				continue
			}

			if escaped {
				escaped = false

				continue
			}

			if quoted && value[i] == '\\' {
				escaped = true

				continue
			}

			if value[i] == '"' {
				quoted = !quoted
			}
		}

		if quoted || escaped {
			return nil, ErrInvalidForwardedIP
		}
	}

	return dst, nil
}

func appendIPFromForwardedParam(dst []string, param string) ([]string, error) {
	name, value, found := strings.Cut(strings.TrimSpace(param), "=")
	if !found || !stringx.EqualFoldASCII(strings.TrimSpace(name), "for") {
		return dst, nil
	}

	value = strings.TrimSpace(value)
	if len(value) == 0 {
		return nil, ErrInvalidForwardedIP
	}

	ip, err := parseForwardedForIP(value)
	if err != nil && !errors.Is(err, errObfuscatedIP) {
		return nil, err
	} else if err == nil {
		dst = append(dst, ip)
	}

	return dst, nil
}

func parseForwardedForIP(value string) (string, error) {
	quoted := false

	if value[0] == '"' {
		unquoted, err := unquoteHTTPQuotedString(value)
		if err != nil {
			return "", err
		}

		value = strings.TrimSpace(unquoted)
		if len(value) == 0 {
			return "", ErrInvalidForwardedIP
		}

		quoted = true
	}

	if stringx.EqualFoldASCII(value, "unknown") || value[0] == '_' {
		return "", errObfuscatedIP
	}

	if value[0] == '[' {
		if !quoted {
			return "", ErrInvalidForwardedIP
		}

		end := strings.IndexByte(value, ']')
		if end < 0 || end+1 != len(value) {
			return "", ErrInvalidForwardedIP
		}

		value = value[1:end]
	}

	if !isIP(value) {
		return "", ErrInvalidForwardedIP
	}

	return value, nil
}

func unquoteHTTPQuotedString(value string) (string, error) {
	if len(value) < 2 || value[len(value)-1] != '"' {
		return "", ErrInvalidForwardedIP
	}

	value = value[1 : len(value)-1]
	if !strings.Contains(value, "\\") {
		return value, nil
	}

	var builder strings.Builder
	builder.Grow(len(value))

	for i := 0; i < len(value); i++ {
		if value[i] != '\\' {
			builder.WriteByte(value[i])

			continue
		}

		i++
		if i == len(value) {
			return "", ErrInvalidForwardedIP
		}

		builder.WriteByte(value[i])
	}

	return builder.String(), nil
}

func isIP(value string) bool {
	return isIPv4(value) || isIPv6(value)
}
