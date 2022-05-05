package oauth2

import (
	"encoding/json"
	"strings"

	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// Audience represents the recipients that the token is intended for.
type Audience []string

// UnmarshalJSON reads an audience from its JSON representation.
func (s *Audience) UnmarshalJSON(b []byte) error {
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return errorchain.NewWithMessage(ErrConfiguration, "failed to unmarshal audience").CausedBy(err)
	}

	switch value := v.(type) {
	case string:
		*s = strings.Split(value, " ")
	case []interface{}:
		array := make([]string, len(value))

		for idx, val := range value {
			s, ok := val.(string)
			if !ok {
				return errorchain.NewWithMessage(ErrConfiguration, "failed to parse audience array")
			}

			array[idx] = s
		}

		*s = array
	default:
		return errorchain.NewWithMessage(ErrConfiguration, "unexpected content for audience")
	}

	return nil
}
