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
	"net/http"

	"github.com/goccy/go-json"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/dadrus/heimdall/internal/rules/provider/kubernetes/api/webhook"
	"github.com/dadrus/heimdall/internal/x"
)

var (
	_ webhook.Request                     = (*request)(nil)
	_ webhook.Response[*request]          = (*response)(nil)
	_ webhook.Review[*request, *response] = (*review)(nil)
)

type (
	request apiextv1.ConversionRequest

	response apiextv1.ConversionResponse

	responseOption func(*response)

	// Adapter for ConversionReview.
	review struct{}
)

// nolint: gochecknoglobals
var knownReasons = map[int32]metav1.StatusReason{
	http.StatusUnauthorized:          metav1.StatusReasonUnauthorized,
	http.StatusForbidden:             metav1.StatusReasonForbidden,
	http.StatusNotFound:              metav1.StatusReasonNotFound,
	http.StatusConflict:              metav1.StatusReasonConflict,
	http.StatusGone:                  metav1.StatusReasonGone,
	http.StatusUnprocessableEntity:   metav1.StatusReasonInvalid,
	http.StatusGatewayTimeout:        metav1.StatusReasonServerTimeout,
	http.StatusRequestTimeout:        metav1.StatusReasonTimeout,
	http.StatusTooManyRequests:       metav1.StatusReasonTooManyRequests,
	http.StatusBadRequest:            metav1.StatusReasonBadRequest,
	http.StatusMethodNotAllowed:      metav1.StatusReasonMethodNotAllowed,
	http.StatusNotAcceptable:         metav1.StatusReasonNotAcceptable,
	http.StatusRequestEntityTooLarge: metav1.StatusReasonRequestEntityTooLarge,
	http.StatusUnsupportedMediaType:  metav1.StatusReasonUnsupportedMediaType,
	http.StatusInternalServerError:   metav1.StatusReasonInternalError,
	http.StatusServiceUnavailable:    metav1.StatusReasonServiceUnavailable,
}

func (r *request) GetUID() string { return string(r.UID) }

func withErrorDetails(details ...metav1.StatusCause) responseOption {
	return func(resp *response) {
		if len(details) > 0 {
			resp.Result.Details = &metav1.StatusDetails{Causes: details}
		}
	}
}

func withConvertedObjects(converted []runtime.RawExtension) responseOption {
	return func(resp *response) {
		if len(converted) > 0 {
			resp.ConvertedObjects = converted
		}
	}
}

func newResponse(code int, msg string, opts ...responseOption) *response {
	resp := &response{
		Result: metav1.Status{
			//nolint:gosec
			// no integer overflow during conversion possible
			Code:    int32(code),
			Status:  x.IfThenElse(code == http.StatusOK, metav1.StatusSuccess, metav1.StatusFailure),
			Message: msg,
		},
	}

	if resp.Result.Status != metav1.StatusSuccess {
		resp.Result.Reason = knownReasons[resp.Result.Code]
	}

	for _, opt := range opts {
		opt(resp)
	}

	return resp
}

func (r *response) Complete(req *request) {
	r.UID = req.UID

	// ensure that we have a valid status code
	if r.Result.Code == 0 {
		r.Result.Code = http.StatusOK
	}
}

func (review) Decode(r *http.Request) (*request, error) {
	cr := apiextv1.ConversionReview{}

	if err := json.NewDecoder(r.Body).Decode(&cr); err != nil {
		return nil, err
	}

	return (*request)(cr.Request), nil
}

func (review) WrapResponse(resp *response) any {
	return apiextv1.ConversionReview{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ConversionReview",
			APIVersion: "apiextensions.k8s.io/v1",
		},
		Response: (*apiextv1.ConversionResponse)(resp),
	}
}
