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
	"time"

	"github.com/goccy/go-json"
	"github.com/rs/zerolog"
)

type Webhook[Req Request, Resp Response[Req]] struct {
	h      Handler[Req, Resp]
	review Review[Req, Resp]
}

func New[Req Request, Resp Response[Req]](
	handler Handler[Req, Resp],
	review Review[Req, Resp],
) *Webhook[Req, Resp] {
	return &Webhook[Req, Resp]{h: handler, review: review}
}

func (wh *Webhook[Req, Resp]) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	log := zerolog.Ctx(ctx)

	if ct := req.Header.Get("Content-Type"); ct != "application/json" {
		log.Error().Msgf("unexpected content type %s", ct)
		rw.WriteHeader(http.StatusBadRequest)

		return
	}

	if val := req.URL.Query().Get("timeout"); len(val) != 0 {
		timeout, err := time.ParseDuration(val)
		if err == nil {
			var cancel context.CancelFunc

			ctx, cancel = context.WithTimeout(ctx, timeout)

			defer cancel()
		}
	}

	reviewReq, err := wh.review.Decode(req)
	if err != nil {
		log.Error().Err(err).Msg("failed decoding request")
		rw.WriteHeader(http.StatusInternalServerError)

		return
	}

	resp := wh.h.Handle(ctx, reviewReq)
	resp.Complete(reviewReq)

	encoded, err := json.Marshal(wh.review.WrapResponse(resp))
	if err != nil {
		log.Error().Err(err).Msg("failed encoding response")
		rw.WriteHeader(http.StatusInternalServerError)

		return
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	_, _ = rw.Write(encoded)
}
