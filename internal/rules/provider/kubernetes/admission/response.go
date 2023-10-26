package admission

import (
	"net/http"
	"strings"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/dadrus/heimdall/internal/x"
)

func NewResponse(code int, msg string, reasons ...string) *Response {
	resp := &Response{
		AdmissionResponse: admissionv1.AdmissionResponse{
			Allowed: x.IfThenElse(code == http.StatusOK, true, false),
			Result: &metav1.Status{
				Code:    int32(code),
				Status:  x.IfThenElse(code == http.StatusOK, "Success", "Failure"),
				Message: msg,
			},
		},
	}

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

	return resp
}

type Response struct {
	admissionv1.AdmissionResponse
}

func (r *Response) complete(req *Request) {
	r.UID = req.UID

	// ensure that we have a valid status code
	if r.Result == nil {
		r.Result = &metav1.Status{}
	}

	if r.Result.Code == 0 {
		r.Result.Code = http.StatusOK
	}
}
