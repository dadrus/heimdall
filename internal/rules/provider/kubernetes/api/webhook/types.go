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

package webhook

import (
	"context"
	"net/http"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type (
	Handler[Req Request, Resp Response[Req]] interface {
		Handle(ctx context.Context, req Req) Resp
	}

	Request interface {
		GetUID() string
	}

	Response[Req Request] interface {
		Complete(req Req)
	}

	Review[Req Request, Resp Response[Req]] interface {
		Decode(r *http.Request) (Req, error)
		WrapResponse(resp Resp) any
	}
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

func StatusCodeToStatusReason(code int32) metav1.StatusReason { return knownReasons[code] }
