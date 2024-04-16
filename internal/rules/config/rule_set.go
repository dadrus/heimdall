// Copyright 2023 Dimitrij Drus <dadrus@gmx.de>
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
	"strings"
	"time"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type MetaData struct {
	Hash    []byte    `json:"-" yaml:"-"`
	Source  string    `json:"-" yaml:"-"`
	ModTime time.Time `json:"-" yaml:"-"`
}

type RuleSet struct {
	MetaData

	Version string `json:"version" yaml:"version"`
	Name    string `json:"name"    yaml:"name"`
	Rules   []Rule `json:"rules"   validate:"dive" yaml:"rules"`
}

func (rs RuleSet) VerifyPathPrefix(prefix string) error {
	for _, rule := range rs.Rules {
		if !strings.HasPrefix(rule.Matcher.Path.Expression, prefix) {
			return errorchain.NewWithMessage(heimdall.ErrConfiguration,
				"path prefix validation failed for rule ID=%s")
		}
	}

	return nil
}
