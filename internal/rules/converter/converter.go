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

package converter

import (
	"bytes"
	"errors"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/goccy/go-json"

	"github.com/dadrus/heimdall/internal/encoding"
	"github.com/dadrus/heimdall/internal/rules/api/v1alpha4"
	"github.com/dadrus/heimdall/internal/rules/api/v1beta1"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var ErrConversion = errors.New("conversion error")

type (
	Converter interface {
		Convert(data []byte, format string) ([]byte, error)
	}

	unstructuredRuleSet map[string]any

	converter struct {
		toVersion string
	}
)

func New(desiredVersion string) Converter {
	return &converter{
		toVersion: desiredVersion,
	}
}

// nolint: cyclop
func (c *converter) Convert(rawObj []byte, format string) ([]byte, error) {
	var (
		urs       unstructuredRuleSet
		err       error
		converted any
	)

	dec := encoding.NewDecoder(encoding.WithSourceContentType(format))
	enc := encoding.NewEncoder(encoding.WithTargetContentType(format))

	if err = dec.Decode(&urs, bytes.NewBuffer(rawObj)); err != nil {
		return nil, errorchain.NewWithMessage(ErrConversion,
			"failed to decode ruleset").CausedBy(err)
	}

	fromVersion := urs.Version()
	if fromVersion == c.toVersion {
		return nil, errorchain.NewWithMessagef(ErrConversion,
			"ruleset is already in the expected version: %s", c.toVersion)
	}

	switch fromVersion {
	case v1alpha4.Version:
		if c.toVersion != v1beta1.Version {
			return nil, errorchain.NewWithMessagef(ErrConversion,
				"unexpected target ruleset version: %s", c.toVersion)
		}

		var sourceRs v1alpha4.RuleSet

		// decoding will always succeed, as it was already successful above
		_ = dec.DecodeMap(&sourceRs, urs)

		converted, err = c.convertV1Alpha4ToV1Beta1(&sourceRs)
	case v1beta1.Version:
		if c.toVersion != v1alpha4.Version {
			return nil, errorchain.NewWithMessagef(
				ErrConversion, "unexpected target ruleset version: %s", c.toVersion)
		}

		var sourceRs v1beta1.RuleSet

		// decoding will always succeed, as it was already successful above
		_ = dec.DecodeMap(&sourceRs, urs)

		converted, err = c.convertV1Beta1ToV1Alpha4(&sourceRs)
	default:
		return nil, errorchain.NewWithMessagef(
			ErrConversion, "unexpected source ruleset version: %s", fromVersion)
	}

	if err != nil {
		return nil, err
	}

	buf := &bytes.Buffer{}
	if err = enc.Encode(converted, buf); err != nil {
		return nil, errorchain.NewWithMessage(ErrConversion, "failed to marshal converted rule set").
			CausedBy(err)
	}

	return buf.Bytes(), nil
}

func (c *converter) convertV1Beta1ToV1Alpha4(sourceRs *v1beta1.RuleSet) (*v1alpha4.RuleSet, error) {
	convertedRules := make([]v1alpha4.Rule, len(sourceRs.Rules))

	for idx, rul := range sourceRs.Rules {
		routes, err := convertObject[[]v1beta1.Route, []v1alpha4.Route](rul.Matcher.Routes)
		if err != nil {
			return nil, errorchain.NewWithMessagef(ErrConversion,
				"failed converting matcher routes for rule %s", rul.ID).CausedBy(err)
		}

		backend, err := convertObject[v1beta1.Backend, v1alpha4.Backend](*rul.Backend)
		if err != nil {
			return nil, errorchain.NewWithMessagef(ErrConversion,
				"failed converting forward_to for rule %s", rul.ID).CausedBy(err)
		}

		hosts := make([]v1alpha4.HostMatcher, len(rul.Matcher.Hosts))
		for idx, host := range rul.Matcher.Hosts {
			hosts[idx] = v1alpha4.HostMatcher{Value: host, Type: "wildcard"}
		}

		executePipeline, err := convertObject[[]v1beta1.Step, []config.MechanismConfig](rul.Execute)
		if err != nil {
			return nil, errorchain.NewWithMessagef(ErrConversion,
				"failed converting execute for rule %s", rul.ID).CausedBy(err)
		}

		errorPipeline, err := convertObject[[]v1beta1.Step, []config.MechanismConfig](rul.ErrorHandler)
		if err != nil {
			return nil, errorchain.NewWithMessagef(ErrConversion,
				"failed converting on_error for rule %s", rul.ID).CausedBy(err)
		}

		convertedRules[idx] = v1alpha4.Rule{
			ID:                     rul.ID,
			EncodedSlashesHandling: v1alpha4.EncodedSlashesHandling(rul.EncodedSlashesHandling),
			Matcher: v1alpha4.Matcher{
				Routes:  routes,
				Scheme:  rul.Matcher.Scheme,
				Methods: rul.Matcher.Methods,
				Hosts:   hosts,
			},
			Backend:      &backend,
			Execute:      executePipeline,
			ErrorHandler: errorPipeline,
		}
	}

	return &v1alpha4.RuleSet{
		Version: c.toVersion,
		Name:    sourceRs.Name,
		Rules:   convertedRules,
	}, nil
}

func (c *converter) convertV1Alpha4ToV1Beta1(sourceRs *v1alpha4.RuleSet) (*v1beta1.RuleSet, error) {
	convertedRules := make([]v1beta1.Rule, len(sourceRs.Rules))

	for idx, rul := range sourceRs.Rules {
		routes, err := convertObject[[]v1alpha4.Route, []v1beta1.Route](rul.Matcher.Routes)
		if err != nil {
			return nil, errorchain.NewWithMessagef(ErrConversion,
				"failed converting matcher routes for rule %s", rul.ID).CausedBy(err)
		}

		backend, err := convertObject[v1alpha4.Backend, v1beta1.Backend](*rul.Backend)
		if err != nil {
			return nil, errorchain.NewWithMessagef(ErrConversion,
				"failed converting forward_to for rule %s", rul.ID).CausedBy(err)
		}

		hosts := make([]string, len(rul.Matcher.Hosts))
		for idx, host := range rul.Matcher.Hosts {
			hosts[idx] = host.Value
		}

		executePipeline, err := convertObject[[]config.MechanismConfig, []v1beta1.Step](rul.Execute)
		if err != nil {
			return nil, errorchain.NewWithMessagef(ErrConversion,
				"failed converting execute for rule %s", rul.ID).CausedBy(err)
		}

		errorPipeline, err := convertObject[[]config.MechanismConfig, []v1beta1.Step](rul.ErrorHandler)
		if err != nil {
			return nil, errorchain.NewWithMessagef(ErrConversion,
				"failed converting on_error for rule %s", rul.ID).CausedBy(err)
		}

		convertedRules[idx] = v1beta1.Rule{
			ID:                     rul.ID,
			EncodedSlashesHandling: v1beta1.EncodedSlashesHandling(rul.EncodedSlashesHandling),
			Matcher: v1beta1.Matcher{
				Routes:  routes,
				Scheme:  rul.Matcher.Scheme,
				Methods: rul.Matcher.Methods,
				Hosts:   hosts,
			},
			Backend:      &backend,
			Execute:      executePipeline,
			ErrorHandler: errorPipeline,
		}
	}

	return &v1beta1.RuleSet{
		Version: c.toVersion,
		Name:    sourceRs.Name,
		Rules:   convertedRules,
	}, nil
}

func (rs unstructuredRuleSet) Version() string { return rs.getStringValue("version") }

func (rs unstructuredRuleSet) getStringValue(key string) string {
	val, ok := rs[key]
	if !ok {
		return ""
	}

	stringVal, ok := val.(string)
	if !ok {
		return ""
	}

	return stringVal
}

func convertObject[From any, To any](from From) (To, error) {
	var to To

	raw, err := json.Marshal(from)
	if err != nil {
		return to, err
	}

	if err := json.Unmarshal(raw, &to); err != nil {
		return to, err
	}

	return to, nil
}
