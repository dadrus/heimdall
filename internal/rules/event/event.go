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

package event

import (
	"github.com/dadrus/heimdall/internal/rules/config"
	"github.com/dadrus/heimdall/internal/rules/rule"
)

type ChangeType uint32

// These are the generalized file operations that can trigger a notification.
const (
	Create ChangeType = 1 << iota
	Remove
	Update
)

func (t ChangeType) String() string {
	switch t {
	case Create:
		return "Create"
	case Remove:
		return "Remove"
	case Update:
		return "Update"
	default:
		return "Unknown"
	}
}

type RuleSetChangedEvent struct {
	Src        string
	Name       string
	Hash       []byte
	Rules      []config.Rule
	ChangeType ChangeType
}

type RuleSetChanged struct {
	Source     string
	Name       string
	Rules      []rule.Rule
	ChangeType ChangeType
}
