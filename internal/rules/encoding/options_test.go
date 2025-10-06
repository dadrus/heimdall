// Copyright 2025 Dimitrij Drus <dadrus@gmx.de>
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

package encoding

import (
	"testing"

	"github.com/go-viper/mapstructure/v2"
	"github.com/stretchr/testify/assert"
)

func TestWithSourceContentType(t *testing.T) {
	t.Parallel()

	for uc, contentType := range map[string]string{
		"empty content type":     "",
		"not empty content type": "foo/bar",
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			var opts decoderOpts

			apply := WithSourceContentType(contentType)

			// WHEN
			apply(&opts)

			// THEN
			if len(contentType) == 0 {
				assert.Empty(t, opts.contentType)
			} else {
				assert.Equal(t, contentType, opts.contentType)
			}
		})
	}
}

func TestWithTypesValidation(t *testing.T) {
	t.Parallel()

	// GIVEN
	var opts decoderOpts

	apply := WithValidator(noopValidator{})

	// WHEN
	apply(&opts)

	// THEN
	assert.IsType(t, noopValidator{}, opts.validator)
}

func TestWithErrorOnUnused(t *testing.T) {
	t.Parallel()

	// GIVEN
	var opts decoderOpts

	apply := WithErrorOnUnused(true)

	// WHEN
	apply(&opts)

	// THEN
	assert.True(t, opts.errorOnUnused)
}

func TestWithEnvVarsSubstitution(t *testing.T) {
	t.Parallel()

	// GIVEN
	var opts decoderOpts

	apply := WithEnvVarsSubstitution(true)

	// WHEN
	apply(&opts)

	// THEN
	assert.True(t, opts.substituteEnvVars)
}

func TestWithDecodeHooks(t *testing.T) {
	t.Parallel()

	// GIVEN
	var opts decoderOpts

	apply := WithDecodeHooks(mapstructure.StringToBasicTypeHookFunc())

	// WHEN
	apply(&opts)

	// THEN
	assert.NotNil(t, opts.decodeHooks)
}

func TestWithTagName(t *testing.T) {
	t.Parallel()

	// GIVEN
	var opts decoderOpts

	apply := WithTagName("foo")

	// WHEN
	apply(&opts)

	// THEN
	assert.Equal(t, "foo", opts.tagName)
}

func TestWithTargetContentType(t *testing.T) {
	t.Parallel()

	// GIVEN
	for uc, contentType := range map[string]string{
		"empty content type":     "",
		"not empty content type": "foo/bar",
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			var opts encoderOpts

			apply := WithTargetContentType(contentType)

			// WHEN
			apply(&opts)

			// THEN
			if len(contentType) == 0 {
				assert.Empty(t, opts.contentType)
			} else {
				assert.Equal(t, contentType, opts.contentType)
			}
		})
	}
}
