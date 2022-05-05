package oauth2

import (
	"encoding/json"
	"strings"

	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// Scopes represents the scopes that the token is granted.
type Scopes []string

// UnmarshalJSON reads scopes from its JSON representation.
func (s *Scopes) UnmarshalJSON(b []byte) error {
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return errorchain.NewWithMessage(ErrConfiguration, "failed to unmarshal scopes").CausedBy(err)
	}

	switch value := v.(type) {
	case string:
		*s = strings.Split(value, " ")
	case []interface{}:
		array := make([]string, len(value))

		for idx, val := range value {
			s, ok := val.(string)
			if !ok {
				return errorchain.NewWithMessage(ErrConfiguration, "failed to parse scopes array")
			}

			array[idx] = s
		}

		*s = array
	default:
		return errorchain.NewWithMessage(ErrConfiguration, "unexpected content for scopes")
	}

	return nil
}
