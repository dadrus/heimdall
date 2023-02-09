package errorhandler

import (
	"encoding/xml"
	"fmt"
	"strings"

	"github.com/goccy/go-json"
)

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
