package errorhandler

import (
	envoy_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/genproto/googleapis/rpc/status"
)

func responseWith(code int) func(err error, verbose bool, mimeType string) (any, error) {
	return func(err error, verbose bool, mimeType string) (any, error) {
		return errorResponse(code, err, verbose, mimeType), nil
	}
}

func errorResponse(code int, err error, verbose bool, mimeType string) *envoy_auth.CheckResponse {
	deniedResponse := &envoy_auth.DeniedHttpResponse{
		Status: &envoy_type.HttpStatus{Code: envoy_type.StatusCode(code)},
	}

	if verbose {
		body, responseType, _ := format(mimeType, err)

		deniedResponse.Headers = []*envoy_core.HeaderValueOption{
			{Header: &envoy_core.HeaderValue{Key: "Content-Type", Value: responseType}},
		}
		deniedResponse.Body = body
	}

	return &envoy_auth.CheckResponse{
		Status:       &status.Status{Code: int32(code)},
		HttpResponse: &envoy_auth.CheckResponse_DeniedResponse{DeniedResponse: deniedResponse},
	}
}
