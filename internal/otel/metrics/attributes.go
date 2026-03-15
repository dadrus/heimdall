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

package metrics

import "go.opentelemetry.io/otel/attribute"

const (
	ResultKey = attribute.Key("result")
)

func Result(value string) attribute.KeyValue { return ResultKey.String(value) }

const (
	RuleIDKey   = attribute.Key("rule.id")
	RuleSetKey  = attribute.Key("ruleset.name")
	ProviderKey = attribute.Key("provider")
)

func RuleID(value string) attribute.KeyValue   { return RuleIDKey.String(value) }
func RuleSet(value string) attribute.KeyValue  { return RuleSetKey.String(value) }
func Provider(value string) attribute.KeyValue { return ProviderKey.String(value) }

const (
	StepIDKey        = attribute.Key("step.id")
	MechanismNameKey = attribute.Key("mechanism.name")
	MechanismKindKey = attribute.Key("mechanism.kind")
)

func StepID(value string) attribute.KeyValue        { return StepIDKey.String(value) }
func MechanismKind(value string) attribute.KeyValue { return MechanismKindKey.String(value) }
func MechanismName(value string) attribute.KeyValue { return MechanismNameKey.String(value) }
