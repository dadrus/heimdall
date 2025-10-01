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
	"strings"

	"github.com/goccy/go-json"
	"github.com/rs/zerolog"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/dadrus/heimdall/internal/conversion"
	"github.com/dadrus/heimdall/internal/rules/provider/kubernetes/api/v1beta1"
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

		spec := cr.Object["spec"]

		convertedSpec, err := rc.convertSpec(spec.(map[string]any), fromVersion, toVersion)
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

		cr.Object["spec"] = convertedSpec
		cr.SetAPIVersion(toVersion.String())
		convertedObjects[idx] = runtime.RawExtension{Object: &cr}
	}

	return newResponse(
		http.StatusOK,
		"rule sets converted",
		withConvertedObjects(convertedObjects),
	)
}

func (rc *rulesetConverter) convertSpec(
	rs map[string]any, fromVersion, toVersion schema.GroupVersion,
) (map[string]any, error) {
	// since conversion is delegated to a converter, which expects
	// the ruleset in a format used for not kubernetes based providers
	// there is a need to tune some fields, like adding the version and
	// after the conversion removing it and a potentially empty name
	// field (see below)
	rs["version"] = strings.TrimPrefix(fromVersion.Version, "v")

	data, err := json.Marshal(rs)
	if err != nil {
		return nil, err
	}

	converter := conversion.NewRuleSetConverter(strings.TrimPrefix(toVersion.Version, "v"))

	result, err := converter.ConvertRuleSet(data)
	if err != nil {
		return nil, err
	}

	var convertedRs map[string]any
	if err = json.Unmarshal(result, &convertedRs); err != nil {
		return nil, err
	}

	delete(convertedRs, "version")
	delete(convertedRs, "name")
	convertedRs["authClassName"] = rs["authClassName"]

	return convertedRs, nil
}
