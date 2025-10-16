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
		resp.Result.Reason = webhook.StatusCodeToStatusReason(resp.Result.Code)
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
