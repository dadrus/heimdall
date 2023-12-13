// Copyright 2023 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package errorhandler

import (
	"encoding/xml"
	"fmt"
	"net/http"

	"github.com/elnormous/contenttype"
	"github.com/goccy/go-json"
	"github.com/rs/zerolog"
)

var supportedMediaTypes = []contenttype.MediaType{ //nolint:gochecknoglobals
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
		return supportedMediaTypes[2], []byte(body.Error()), nil
	}
}

func errorWriter(options *opts, code int) func(rw http.ResponseWriter, req *http.Request, err error) {
	return func(rw http.ResponseWriter, req *http.Request, err error) {
		var (
			mt   contenttype.MediaType
			body []byte
		)

		if options.verboseErrors {
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
			// Cannot do anything else here if writing fails
			//nolint:errcheck
			rw.Write(body)
		}
	}
}
