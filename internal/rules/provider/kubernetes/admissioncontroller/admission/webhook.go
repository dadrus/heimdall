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

package admission

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/goccy/go-json"
	"github.com/rs/zerolog"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

//go:generate mockery --name Handler --structname HandlerMock --inpackage --testonly

type Handler interface {
	Handle(ctx context.Context, req *Request) *Response
}

type Webhook struct {
	h Handler
}

func NewWebhook(handler Handler) *Webhook {
	return &Webhook{h: handler}
}

func (wh *Webhook) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	log := zerolog.Ctx(ctx)

	if contentType := req.Header.Get("Content-Type"); contentType != "application/json" {
		log.Error().Msgf("unable to process a request with an unknown content type %s", contentType)
		wh.writeResponse(log, rw, NewResponse(http.StatusBadRequest,
			fmt.Sprintf("unexpected contentType=%s, expected application/json", contentType)))

		return
	}

	ar := admissionv1.AdmissionReview{}
	if err := json.NewDecoder(req.Body).Decode(&ar); err != nil {
		log.Error().Err(err).Msg("unable to decode the request")
		wh.writeResponse(log, rw, NewResponse(http.StatusBadRequest, "failed decoding request", err.Error()))

		return
	}

	if val := req.URL.Query().Get("timeout"); len(val) != 0 {
		timeout, err := time.ParseDuration(val)
		if err != nil {
			log.Warn().Err(err).Msg("Failed parsing timeout query parameter. Ignoring it.")
		} else {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, timeout)

			defer cancel()
		}
	}

	log.Info().
		Str("_uid", string(ar.Request.UID)).
		Str("_kind", ar.Request.Kind.String()).
		Str("_ressource", ar.Request.Resource.String()).
		Msg("Handling request")

	reviewRequest := &Request{AdmissionRequest: *ar.Request}

	reviewResponse := wh.h.Handle(ctx, reviewRequest)
	reviewResponse.complete(reviewRequest)

	wh.writeResponse(log, rw, reviewResponse)
}

func (wh *Webhook) writeResponse(log *zerolog.Logger, rw http.ResponseWriter, response *Response) {
	wh.writeAdmissionResponse(log, rw,
		admissionv1.AdmissionReview{
			TypeMeta: metav1.TypeMeta{
				Kind:       "AdmissionReview",
				APIVersion: "admission.k8s.io/v1",
			},
			Response: &response.AdmissionResponse,
		},
	)
}

func (wh *Webhook) writeAdmissionResponse(log *zerolog.Logger, rw http.ResponseWriter, ar admissionv1.AdmissionReview) {
	res, err := json.Marshal(ar)
	if err != nil {
		log.Error().Err(err).Msg("Failed to encode the response")
		rw.WriteHeader(http.StatusInternalServerError)

		return
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	rw.Write(res) //nolint:errcheck
}
