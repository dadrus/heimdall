package admission

import (
	"net/http"

	"github.com/goccy/go-json"
	"gomodules.xyz/jsonpatch/v2"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/dadrus/heimdall/internal/x"
)

func NewResponse(code int, reason ...string) *Response {
	resp := &Response{
		AdmissionResponse: admissionv1.AdmissionResponse{
			Allowed: x.IfThenElse(code == http.StatusOK, true, false),
			Result:  &metav1.Status{Code: int32(code)},
		},
	}

	if len(reason) > 0 {
		resp.Result.Reason = metav1.StatusReason(reason[0])
	}

	return resp
}

type Response struct {
	admissionv1.AdmissionResponse

	Patches []jsonpatch.JsonPatchOperation
}

func (r *Response) complete(req *Request) error {
	r.UID = req.UID

	// ensure that we have a valid status code
	if r.Result == nil {
		r.Result = &metav1.Status{}
	}

	if r.Result.Code == 0 {
		r.Result.Code = http.StatusOK
	}

	if len(r.Patches) == 0 {
		return nil
	}

	var err error

	r.Patch, err = json.Marshal(r.Patches)
	if err != nil {
		return err
	}

	patchType := admissionv1.PatchTypeJSONPatch
	r.PatchType = &patchType

	return nil
}
