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

package parser

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/knadh/koanf/providers/env/v2"
	"github.com/knadh/koanf/v2"
	"gopkg.in/yaml.v3"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

var isNumRegex = regexp.MustCompile(`^\d+$`)

func messageDigest(val, hash string) string {
	mds := sha256.New()
	mds.Write(stringx.ToBytes(val))
	mds.Write(stringx.ToBytes(hash))

	return hex.EncodeToString(mds.Sum(nil))
}

func toRealType(val string) any {
	var parsed map[string]any

	// here we're using the ability of the yaml parser to "guess" the type and convert the given string to it.
	// this is not the fastest way, but ok for now.
	yaml.Unmarshal(stringx.ToBytes("val: "+val), &parsed) // nolint: errcheck

	return parsed["val"]
}

func convert(key, val, hash string) (string, any, string) {
	parts := strings.Split(key, ".")
	if len(parts) == 0 {
		return key, toRealType(val), messageDigest(val, hash)
	}

	var (
		pos             int
		prefix, postfix string
	)

	pos = -1

	for idx, part := range parts {
		if !isNumRegex.MatchString(part) {
			continue
		}

		pos, _ = strconv.Atoi(part)
		prefix = strings.Join(parts[:idx], ".")
		postfix = strings.Join(parts[idx+1:], ".")

		break
	}

	if pos == -1 {
		return key, toRealType(val), messageDigest(val, hash)
	}

	slice := make([]any, pos+1)

	newKey, newVal, hash := convert(postfix, val, messageDigest(val, hash))
	if len(newKey) != 0 {
		slice[pos] = map[string]any{newKey: newVal}
	} else {
		slice[pos] = newVal
	}

	return prefix, slice, hash
}

func cleanSuffix(val any) any {
	result := make(map[string]any)

	switch t := val.(type) {
	case map[string]any:
		for k, v := range t {
			parts := strings.Split(k, "#")

			result[parts[0]] = cleanSuffix(v)
		}

		return result
	default:
		return val
	}
}

func koanfFromEnv(prefix string) (*koanf.Koanf, error) {
	parser := koanf.New(".")

	provider := env.Provider(".", env.Opt{
		Prefix: prefix,
		TransformFunc: func(key, val string) (string, any) {
			tmp := strings.ReplaceAll(strings.ToLower(strings.TrimPrefix(key, prefix)), "__", `\:\`)
			tmp = strings.ReplaceAll(tmp, "_", ".")
			normalizedKey := strings.ReplaceAll(tmp, `\:\`, "_")

			newKey, newVal, hash := convert(normalizedKey, val, normalizedKey)

			return fmt.Sprintf("%s#%s", newKey, hash), newVal
		},
	})

	err := parser.Load(provider,
		nil,
		koanf.WithMergeFunc(func(src, dest map[string]any) error {
			for key, val := range src {
				parts := strings.Split(key, "#")
				key := parts[0]

				dest[key] = merge(dest[key], val)
			}

			return nil
		}),
	)
	if err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed to parse environment variables to config").CausedBy(err)
	}

	return parser, nil
}
