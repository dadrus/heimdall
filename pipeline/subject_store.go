package pipeline

import "net/http"

type Subject struct {
	Id         string                 `json:"id"`
	Attributes map[string]interface{} `json:"attributes"`
}

type SubjectContext struct {
	Subject *Subject
	Header  http.Header
}
