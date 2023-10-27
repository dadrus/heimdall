package admission

import admissionv1 "k8s.io/api/admission/v1"

type Request struct {
	admissionv1.AdmissionRequest
}
