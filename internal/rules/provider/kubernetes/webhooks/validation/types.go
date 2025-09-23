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

package validation

import (
	"net/http"
	"strings"

	"github.com/goccy/go-json"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/dadrus/heimdall/internal/rules/provider/kubernetes/api/webhook"
	"github.com/dadrus/heimdall/internal/x"
)

var (
	_ webhook.Request                     = (*request)(nil)
	_ webhook.Response[*request]          = (*response)(nil)
	_ webhook.Review[*request, *response] = (*review)(nil)
)

type (
	request admissionv1.AdmissionRequest

	response admissionv1.AdmissionResponse

	responseOption func(*response)

	// Adapter for AdmissionReview
	review struct{}
)

func (r request) GetUID() string { return string(r.UID) }

func withReasons(reasons ...string) responseOption {
	return func(resp *response) {
		if len(reasons) > 0 {
			resp.Result.Details = &metav1.StatusDetails{Causes: make([]metav1.StatusCause, len(reasons))}

			for idx, reason := range reasons {
				resp.Result.Details.Causes[idx] = metav1.StatusCause{Message: reason}
			}

			// Unfortunately details alone are not sufficient. At least when using kubectl
			// if no Reason is set, only the Message (see above) is printed, which
			// typically does not provide any details which could help resolving the issue
			resp.Result.Reason = metav1.StatusReason(strings.Join(reasons, "; "))
		}
	}
}

func newResponse(code int, msg string, opts ...responseOption) *response {
	resp := &response{
		Allowed: x.IfThenElse(code == http.StatusOK, true, false),
		Result: &metav1.Status{
			//nolint:gosec
			// no integer overflow during conversion possible
			Code:    int32(code),
			Status:  x.IfThenElse(code == http.StatusOK, metav1.StatusSuccess, metav1.StatusFailure),
			Message: msg,
		},
	}

	for _, opt := range opts {
		opt(resp)
	}

	return resp
}

func (r *response) Complete(req *request) {
	r.UID = req.UID

	// ensure that we have a valid status code
	if r.Result == nil {
		r.Result = &metav1.Status{}
	}

	if r.Result.Code == 0 {
		r.Result.Code = http.StatusOK
	}
}

func (review) Decode(r *http.Request) (*request, error) {
	ar := admissionv1.AdmissionReview{}

	if err := json.NewDecoder(r.Body).Decode(&ar); err != nil {
		return nil, err
	}

	return (*request)(ar.Request), nil
}

func (review) WrapResponse(resp *response) any {
	return admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			Kind:       "AdmissionReview",
			APIVersion: "admission.k8s.io/v1",
		},
		Response: (*admissionv1.AdmissionResponse)(resp),
	}
}
