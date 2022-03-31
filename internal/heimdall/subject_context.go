package heimdall

import "net/http"

type Subject struct {
	ID         string      `json:"id"`
	Attributes interface{} `json:"attributes"`
}

type SubjectContext struct {
	Subject *Subject
	Header  http.Header
}
