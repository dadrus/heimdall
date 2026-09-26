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

package nonce

import "time"

type createConfig struct {
	binding [nonceBindingSize]byte
}

type validateConfig struct {
	binding [nonceBindingSize]byte
	maxAge  time.Duration
}

type CreateOption interface {
	applyCreate(cfg *createConfig)
}

type ValidateOption interface {
	applyValidate(cfg *validateConfig)
}

type bindingOption [nonceBindingSize]byte

func (o bindingOption) applyCreate(cfg *createConfig)     { cfg.binding = o }
func (o bindingOption) applyValidate(cfg *validateConfig) { cfg.binding = o }

func WithBinding(binding [nonceBindingSize]byte) bindingOption { return binding }

type maxAgeOption time.Duration

func (o maxAgeOption) applyValidate(cfg *validateConfig) { cfg.maxAge = time.Duration(o) }

func WithMaxAge(maxAge time.Duration) maxAgeOption { return maxAgeOption(maxAge) }
