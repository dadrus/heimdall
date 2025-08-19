package conversion

import (
	"net/http"
	"strings"

	"github.com/goccy/go-json"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/dadrus/heimdall/internal/rules/provider/kubernetes/controller/webhook"
	"github.com/dadrus/heimdall/internal/x"
)

var (
	_ webhook.Request                     = (*request)(nil)
	_ webhook.Response[*request]          = (*response)(nil)
	_ webhook.Review[*request, *response] = (*review)(nil)
)

type (
	request struct {
		apiextv1.ConversionRequest
	}

	response struct {
		apiextv1.ConversionResponse
	}

	responseOption func(*response)

	// Adapter for ConversionReview
	review struct{}
)

func (r *request) GetUID() string { return string(r.UID) }

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

func withConvertedObjects(converted []runtime.RawExtension) responseOption {
	return func(resp *response) {
		if len(converted) > 0 {
			resp.ConvertedObjects = converted
		}
	}
}

func newResponse(code int, msg string, opts ...responseOption) *response {
	resp := &response{
		ConversionResponse: apiextv1.ConversionResponse{
			Result: metav1.Status{
				//nolint:gosec
				// no integer overflow during conversion possible
				Code:    int32(code),
				Status:  x.IfThenElse(code == http.StatusOK, metav1.StatusSuccess, metav1.StatusFailure),
				Message: msg,
			},
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
	if r.Result.Code == 0 {
		r.Result.Code = http.StatusOK
	}
}

func (review) Decode(r *http.Request) (*request, error) {
	cr := apiextv1.ConversionReview{}

	if err := json.NewDecoder(r.Body).Decode(&cr); err != nil {
		return nil, err
	}

	return &request{ConversionRequest: *cr.Request}, nil
}

func (review) WrapResponse(resp *response) any {
	return apiextv1.ConversionReview{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ConversionReview",
			APIVersion: "apiextensions.k8s.io/v1",
		},
		Response: &resp.ConversionResponse,
	}
}
