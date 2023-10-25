package admission

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/goccy/go-json"
	"github.com/rs/zerolog"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Handler interface {
	Handle(context.Context, *Request) *Response
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
			fmt.Sprintf("contentType=%s, expected application/json", contentType)))

		return
	}

	ar := admissionv1.AdmissionReview{}
	if err := json.NewDecoder(req.Body).Decode(&ar); err != nil {
		log.Error().Err(err).Msg("unable to decode the request")
		wh.writeResponse(log, rw, NewResponse(http.StatusBadRequest, err.Error()))

		return
	}

	if val := req.URL.Query().Get("timeout"); len(val) != 0 {
		timeout, err := strconv.Atoi(val)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to convert timeout query parameter. Ignoring it.")
		}

		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(timeout)*time.Second)

		defer cancel()
	}

	log.Info().
		Str("UID", string(ar.Request.UID)).
		Str("kind", ar.Request.Kind.String()).
		Str("ressource", ar.Request.Resource.String()).
		Msg("Handling request")

	reviewRequest := &Request{AdmissionRequest: *ar.Request}

	reviewResponse := wh.h.Handle(ctx, reviewRequest)
	if err := reviewResponse.complete(reviewRequest); err != nil {
		log.Error().Err(err).Msg("unable to finalize the response")
		wh.writeResponse(log, rw, NewResponse(http.StatusInternalServerError, err.Error()))

		return
	}

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
	rw.WriteHeader(int(ar.Response.Result.Code))
	rw.Write(res) //nolint:errcheck
}
