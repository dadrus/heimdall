package authenticators

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/dadrus/heimdall/internal/rules/mechanisms/authenticators/extractors"
)

type BodyParameterForwardStrategy struct {
	Name string `mapstructure:"name"`
}

func (s *BodyParameterForwardStrategy) Apply(src extractors.AuthData, req *http.Request) {
	contentType := req.Header.Get("Content-Type")

	var value string

	if contentType == "application/x-www-form-urlencoded" {
		value = url.Values{s.Name: []string{src.Value()}}.Encode()
	} else {
		// json
		value = fmt.Sprintf(`{ "%s": "%s" }`, s.Name, src.Value())
	}

	req.Body = io.NopCloser(bytes.NewBuffer([]byte(value)))
}
