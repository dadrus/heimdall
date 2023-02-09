package errorhandler

import (
	"encoding/xml"
	"fmt"
	"strings"

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

func format(accepted string, body any) (string, string, error) {
	contentType := negotiate(accepted, "text/html", "application/json", "test/plain", "application/xml")

	switch contentType {
	case "text/html":
		return fmt.Sprintf("<p>%s</p>", body), contentType, nil
	case "application/json":
		res, err := json.Marshal(body)

		return string(res), contentType, err
	case "application/xml":
		res, err := xml.Marshal(body)

		return string(res), contentType, err
	case "test/plain":
		fallthrough
	default:
		return fmt.Sprintf("%s", body), contentType, nil
	}
}

func negotiate(accepted string, offered ...string) string {
	if len(accepted) == 0 {
		return offered[0]
	}

	spec, commaPos, header := "", 0, accepted
	for len(header) > 0 && commaPos != -1 {
		commaPos = strings.IndexByte(header, ',')
		if commaPos != -1 {
			spec = strings.Trim(header[:commaPos], " ")
		} else {
			spec = strings.TrimLeft(header, " ")
		}

		if factorSign := strings.IndexByte(spec, ';'); factorSign != -1 {
			spec = spec[:factorSign]
		}

		for _, offer := range offered {
			if len(offer) == 0 {
				continue
			} else if spec == "*/*" {
				return offer
			}

			if strings.Contains(spec, offer) {
				return offer
			}
		}

		if commaPos != -1 {
			header = header[commaPos+1:]
		}
	}

	return ""
}
