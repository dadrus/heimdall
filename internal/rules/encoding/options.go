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

type Validator interface {
	Validate(typ any) error
}

type ValidatorFunc func(typ any) error

func (v ValidatorFunc) Validate(typ any) error { return v(typ) }

type noopValidator struct{}

func (noopValidator) Validate(_ any) error { return nil }

type decoderOpts struct {
	contentType       string
	substituteEnvVars bool
	validator         Validator
	errorOnUnused     bool
}

type DecoderOption func(*decoderOpts)

func WithSourceContentType(contentType string) DecoderOption {
	return func(opts *decoderOpts) {
		if len(contentType) != 0 {
			opts.contentType = contentType
		}
	}
}

func WithEnvVarsSubstitution(flag bool) DecoderOption {
	return func(opts *decoderOpts) {
		opts.substituteEnvVars = flag
	}
}

func WithValidator(validator Validator) DecoderOption {
	return func(opts *decoderOpts) {
		if validator != nil {
			opts.validator = validator
		}
	}
}

func WithErrorOnUnused(flag bool) DecoderOption {
	return func(opts *decoderOpts) {
		opts.errorOnUnused = flag
	}
}

type encoderOpts struct {
	contentType string
}

type EncoderOption func(*encoderOpts)

func WithTargetContentType(contentType string) EncoderOption {
	return func(opts *encoderOpts) {
		if len(contentType) != 0 {
			opts.contentType = contentType
		}
	}
}
