package errorhandler

import (
	"encoding/xml"
	"fmt"

	"github.com/elnormous/contenttype"
	envoy_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/goccy/go-json"
	"google.golang.org/genproto/googleapis/rpc/status"
)

func responseWith(code int) func(err error, verbose bool, mimeType string) (any, error) {
	return func(err error, verbose bool, mimeType string) (any, error) {
		return errorResponse(code, err, verbose, mimeType), nil
	}
}

func errorResponse(code int, decErr error, verbose bool, mimeType string) *envoy_auth.CheckResponse {
	deniedResponse := &envoy_auth.DeniedHttpResponse{
		Status: &envoy_type.HttpStatus{Code: envoy_type.StatusCode(code)},
	}

	if verbose {
		contentType := "text/html"

		mt, _, err := contenttype.GetAcceptableMediaTypeFromHeader(
			mimeType, []contenttype.MediaType{
				{Type: "application", Subtype: "json"},
				{Type: "application", Subtype: "xml"},
				{Type: "text", Subtype: "html"},
				{Type: "text", Subtype: "plain"},
			})
		if err == nil {
			contentType = mt.MIME()
		}

		body, _ := format(contentType, decErr)

		deniedResponse.Headers = []*envoy_core.HeaderValueOption{
			{Header: &envoy_core.HeaderValue{Key: "Content-Type", Value: contentType}},
		}
		deniedResponse.Body = body
	}

	return &envoy_auth.CheckResponse{
		Status:       &status.Status{Code: int32(code)},
		HttpResponse: &envoy_auth.CheckResponse_DeniedResponse{DeniedResponse: deniedResponse},
	}
}

func format(mimeType string, body any) (string, error) {
	switch mimeType {
	case "text/html":
		return fmt.Sprintf("<p>%s</p>", body), nil
	case "application/json":
		res, err := json.Marshal(body)

		return string(res), err
	case "application/xml":
		res, err := xml.Marshal(body)

		return string(res), err
	case "test/plain":
		fallthrough
	default:
		return fmt.Sprintf("%s", body), nil
	}
}
