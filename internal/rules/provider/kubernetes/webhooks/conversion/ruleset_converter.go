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

package conversion

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/goccy/go-json"
	"github.com/rs/zerolog"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	cfgv1alpha4 "github.com/dadrus/heimdall/internal/rules/api/v1alpha4"
	cfgv1beta1 "github.com/dadrus/heimdall/internal/rules/api/v1beta1"
	"github.com/dadrus/heimdall/internal/rules/provider/kubernetes/api/v1alpha4"
	"github.com/dadrus/heimdall/internal/rules/provider/kubernetes/api/v1beta1"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var ErrConversion = errors.New("conversion error")

type rulesetConverter struct{}

// nolint: funlen
func (rc *rulesetConverter) Handle(ctx context.Context, req *request) *response {
	log := zerolog.Ctx(ctx)
	convertedObjects := make([]runtime.RawExtension, len(req.Objects))

	if len(req.Objects) == 0 {
		log.Error().Msg("no objects to convert provided")

		return newResponse(
			http.StatusBadRequest,
			"no objects to convert provided",
			withErrorDetails(metav1.StatusCause{
				Type:    metav1.CauseTypeFieldValueRequired,
				Field:   "Objects",
				Message: "no objects to convert provided",
			}),
		)
	}

	toVersion, err := schema.ParseGroupVersion(req.DesiredAPIVersion)
	if err != nil {
		log.Error().Err(err).Msg("malformed DesiredAPIVersion in request")

		return newResponse(
			http.StatusBadRequest,
			"failed to parse DesiredAPIVersion",
			withErrorDetails(metav1.StatusCause{
				Type:    metav1.CauseTypeFieldValueInvalid,
				Field:   "DesiredAPIVersion",
				Message: err.Error(),
			}),
		)
	}

	for idx, obj := range req.Objects {
		cr := unstructured.Unstructured{}
		if err := cr.UnmarshalJSON(obj.Raw); err != nil {
			log.Error().Err(err).Msg("could not unmarshal object")

			return newResponse(
				http.StatusBadRequest,
				fmt.Sprintf("failed to unmarshal object at index %d", idx),
				withErrorDetails(metav1.StatusCause{
					Type:    metav1.CauseTypeFieldValueInvalid,
					Field:   fmt.Sprintf("Objects[%d]", idx),
					Message: err.Error(),
				}),
			)
		}

		// error ignored as the validity of the apiVersion is already checked
		// in UnmarshalJSON above
		fromVersion, _ := schema.ParseGroupVersion(cr.GetAPIVersion())

		objKind := cr.GetKind()
		if objKind != v1beta1.ResourceName {
			log.Error().Msgf("unexpected resource kind in object at index %d - expected %s, got %s",
				idx, v1beta1.ResourceName, objKind)

			return newResponse(
				http.StatusBadRequest,
				"expected "+v1beta1.ResourceName+" but got "+objKind,
				withErrorDetails(metav1.StatusCause{
					Type:    metav1.CauseTypeFieldValueInvalid,
					Field:   fmt.Sprintf("Objects[%d].kind", idx),
					Message: "expected " + v1beta1.ResourceName + ", got " + objKind,
				}),
			)
		}

		if fromVersion.Version == toVersion.Version {
			log.Error().Msgf("rule set at index %d is already in the expected version: %s",
				idx, toVersion.String())

			return newResponse(
				http.StatusBadRequest,
				"rule set is already in the expected version: "+toVersion.String(),
				withErrorDetails(metav1.StatusCause{
					Type:    metav1.CauseTypeFieldValueInvalid,
					Field:   fmt.Sprintf("Objects[%d].apiVersion", idx),
					Message: "rule set is already in the expected version: " + toVersion.String(),
				}),
			)
		}

		converted, err := rc.convertSpec(obj.Raw, fromVersion, toVersion)
		if err != nil {
			log.Error().Err(err).Msg("failed to convert rule set")

			return newResponse(
				http.StatusBadRequest,
				"failed to convert rule set",
				withErrorDetails(metav1.StatusCause{
					Type:    metav1.CauseTypeFieldValueInvalid,
					Field:   fmt.Sprintf("Objects[%d]", idx),
					Message: err.Error(),
				}),
			)
		}

		cr.Object["spec"] = converted
		cr.SetAPIVersion(toVersion.String())
		convertedObjects[idx] = runtime.RawExtension{Object: &cr}
	}

	return newResponse(
		http.StatusOK,
		"rule sets converted",
		withConvertedObjects(convertedObjects),
	)
}

// nolint: gocognit, cyclop, funlen
func (rc *rulesetConverter) convertSpec(rawObj []byte, fromVersion, toVersion schema.GroupVersion) (any, error) {
	switch fromVersion {
	case v1alpha4.GroupVersion:
		if toVersion != v1beta1.GroupVersion {
			return nil, errorchain.NewWithMessagef(
				ErrConversion, "unexpected target conversion version %s", toVersion)
		}

		var (
			err error
			rs  v1alpha4.RuleSet
		)
		if err = json.Unmarshal(rawObj, &rs); err != nil {
			return nil, err
		}

		converted := make([]cfgv1beta1.Rule, len(rs.Spec.Rules))

		for idx, rul := range rs.Spec.Rules {
			routes, err := convertObject[[]cfgv1alpha4.Route, []cfgv1beta1.Route](rul.Matcher.Routes)
			if err != nil {
				return nil, err
			}

			backend, err := convertObject[cfgv1alpha4.Backend, cfgv1beta1.Backend](*rul.Backend)
			if err != nil {
				return nil, err
			}

			hosts := make([]string, len(rul.Matcher.Hosts))
			for idx, host := range rul.Matcher.Hosts {
				hosts[idx] = host.Value
			}

			converted[idx] = cfgv1beta1.Rule{
				ID:                     rul.ID,
				EncodedSlashesHandling: rul.EncodedSlashesHandling,
				Matcher: cfgv1beta1.Matcher{
					Routes:  routes,
					Scheme:  rul.Matcher.Scheme,
					Methods: rul.Matcher.Methods,
					Hosts:   hosts,
				},
				Backend:      &backend,
				Execute:      rul.Execute,
				ErrorHandler: rul.ErrorHandler,
			}
		}

		return v1beta1.RuleSetSpec{
			AuthClassName: rs.Spec.AuthClassName,
			Rules:         converted,
		}, nil
	case v1beta1.GroupVersion:
		if toVersion != v1alpha4.GroupVersion {
			return nil, errorchain.NewWithMessagef(
				ErrConversion, "unexpected target conversion version %s", toVersion)
		}

		var (
			err error
			rs  v1beta1.RuleSet
		)
		if err = json.Unmarshal(rawObj, &rs); err != nil {
			return nil, err
		}

		converted := make([]cfgv1alpha4.Rule, len(rs.Spec.Rules))

		for idx, rul := range rs.Spec.Rules {
			routes, err := convertObject[[]cfgv1beta1.Route, []cfgv1alpha4.Route](rul.Matcher.Routes)
			if err != nil {
				return nil, err
			}

			backend, err := convertObject[cfgv1beta1.Backend, cfgv1alpha4.Backend](*rul.Backend)
			if err != nil {
				return nil, err
			}

			hosts := make([]cfgv1alpha4.HostMatcher, len(rul.Matcher.Hosts))
			for idx, host := range rul.Matcher.Hosts {
				hosts[idx] = cfgv1alpha4.HostMatcher{Value: host, Type: "wildcard"}
			}

			converted[idx] = cfgv1alpha4.Rule{
				ID:                     rul.ID,
				EncodedSlashesHandling: rul.EncodedSlashesHandling,
				Matcher: cfgv1alpha4.Matcher{
					Routes:  routes,
					Scheme:  rul.Matcher.Scheme,
					Methods: rul.Matcher.Methods,
					Hosts:   hosts,
				},
				Backend:      &backend,
				Execute:      rul.Execute,
				ErrorHandler: rul.ErrorHandler,
			}
		}

		return v1alpha4.RuleSetSpec{
			AuthClassName: rs.Spec.AuthClassName,
			Rules:         converted,
		}, nil
	default:
		return nil, errorchain.NewWithMessagef(
			ErrConversion, "unexpected source conversion version %s", fromVersion)
	}
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
