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

package admissioncontroller

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/goccy/go-json"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/rules/config"
	"github.com/dadrus/heimdall/internal/rules/provider/kubernetes/admissioncontroller/admission"
	"github.com/dadrus/heimdall/internal/rules/provider/kubernetes/api/v1beta1"
	"github.com/dadrus/heimdall/internal/rules/rule"
)

var ErrInvalidObject = errors.New("only rule sets are supported here")

type rulesetValidator struct {
	f  rule.Factory
	ac string
}

func (rv *rulesetValidator) Handle(ctx context.Context, req *admission.Request) *admission.Response {
	log := zerolog.Ctx(ctx)

	rs, err := rv.ruleSetFrom(req)
	if err != nil {
		log.Error().Err(err).Msg("could not parse rule set")

		return admission.NewResponse(http.StatusBadRequest, "failed parsing RuleSet", err.Error())
	}

	if rs.Spec.AuthClassName != rv.ac {
		msg := fmt.Sprintf(
			"RuleSet ignored due to authClassName mismatch (namespace=%s, name=%s, uid=%s)",
			rs.Namespace, rs.Name, rs.UID)
		log.Debug().Msg(msg)

		// Responding with ok here as otherwise, if multiple deployments exist, the api server will not allow
		// deploying the ruleset resource, even if another deployment was successfully able validating the rule set.
		// When the resource will be made available to this instance upon deployment, it will anyway be filtered
		// due the authClassName mismatch and not loaded.
		return admission.NewResponse(http.StatusOK, msg)
	}

	ruleSet := &config.RuleSet{
		MetaData: config.MetaData{
			Source:  fmt.Sprintf("%s:%s:%s", "kubernetes", rs.Namespace, rs.UID),
			ModTime: time.Now(),
		},
		Version: rv.mapVersion(rs.APIVersion),
		Name:    rs.Name,
		Rules:   rs.Spec.Rules,
	}

	var errs []string

	for _, rc := range ruleSet.Rules {
		_, err = rv.f.CreateRule(ruleSet.Version, ruleSet.Source, rc)
		if err != nil {
			errs = append(errs, err.Error())
		}
	}

	if len(errs) != 0 {
		return admission.NewResponse(http.StatusForbidden, "RuleSet invalid", errs...)
	}

	return admission.NewResponse(http.StatusOK, "RuleSet valid")
}

func (rv *rulesetValidator) ruleSetFrom(req *admission.Request) (*v1beta1.RuleSet, error) {
	if req.Kind.Kind != "RuleSet" {
		return nil, ErrInvalidObject
	}

	p := &v1beta1.RuleSet{}
	err := json.Unmarshal(req.Object.Raw, p)

	return p, err
}

func (rv *rulesetValidator) mapVersion(_ string) string {
	// currently the only possible version is v1beta1, which is mapped to the version "1beta1" used internally
	return "1beta1"
}
