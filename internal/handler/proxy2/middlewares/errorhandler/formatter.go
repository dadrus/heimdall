package errorhandler

import (
	"encoding/xml"
	"fmt"
	"net/http"

	"github.com/elnormous/contenttype"
	"github.com/goccy/go-json"
	"github.com/rs/zerolog"
)

var supportedMediaTypes = []contenttype.MediaType{
	contenttype.NewMediaType("text/html"),
	contenttype.NewMediaType("application/json"),
	contenttype.NewMediaType("text/plain"),
	contenttype.NewMediaType("application/xml"),
}

func format(req *http.Request, body error) (contenttype.MediaType, []byte, error) {
	mediaType, _, err := contenttype.GetAcceptableMediaType(req, supportedMediaTypes)
	if err != nil {
		return contenttype.MediaType{}, nil, err
	}

	// Format based on the accept content type
	switch mediaType.Subtype {
	case "html":
		return mediaType, []byte(fmt.Sprintf("<p>%s</p>", body)), nil
	case "json":
		res, err := json.Marshal(body)

		return mediaType, res, err
	case "xml":
		res, err := xml.Marshal(body)

		return mediaType, res, err
	case "plain":
		fallthrough
	default:
		return supportedMediaTypes[2], []byte(fmt.Sprintf("%s", body)), nil
	}
}

func errorWriter(o *opts, code int) func(rw http.ResponseWriter, req *http.Request, err error) {
	return func(rw http.ResponseWriter, req *http.Request, err error) {
		var (
			mt   contenttype.MediaType
			body []byte
		)

		if o.verboseErrors {
			mt, body, err = format(req, err)
			if err != nil {
				zerolog.Ctx(req.Context()).Warn().Err(err).Msg("Response format negotiation failed. No body is sent")
			}
		}

		if len(body) != 0 {
			rw.Header().Set("Content-Type", mt.String())
			rw.Header().Set("X-Content-Type-Options", "nosniff")
		}

		rw.WriteHeader(code)

		if len(body) != 0 {
			rw.Write(body)
		}
	}
}
