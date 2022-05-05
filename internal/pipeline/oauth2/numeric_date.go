package oauth2

import (
	"strconv"
	"time"

	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// NumericDate represents date and time as the number of seconds since the
// epoch, ignoring leap seconds. Non-integer values can be represented
// in the serialized format, but we round to the nearest second.
// See RFC7519 Section 2: https://tools.ietf.org/html/rfc7519#section-2
type NumericDate int64

// UnmarshalJSON reads a date from its JSON representation.
func (n *NumericDate) UnmarshalJSON(b []byte) error {
	const floatPrecision = 64

	f, err := strconv.ParseFloat(string(b), floatPrecision)
	if err != nil {
		return errorchain.NewWithMessage(ErrConfiguration, "failed to parse date").CausedBy(err)
	}

	*n = NumericDate(f)

	return nil
}

// Time returns time.Time representation of NumericDate.
func (n *NumericDate) Time() time.Time {
	if n == nil {
		return time.Time{}
	}

	return time.Unix(int64(*n), 0)
}
