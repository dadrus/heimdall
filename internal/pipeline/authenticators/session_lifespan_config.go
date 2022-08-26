package authenticators

import (
	"errors"
	"strconv"
	"time"

	"github.com/tidwall/gjson"

	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var ErrSessionLifespanParseError = errors.New("session lifespan parse error")

type SessionLifespanConfig struct {
	ActiveField    string        `mapstructure:"active"`
	IssuedAtField  string        `mapstructure:"issued_at"`
	NotBeforeField string        `mapstructure:"not_before"`
	NotAfterField  string        `mapstructure:"not_after"`
	TimeFormat     string        `mapstructure:"time_format"`
	ValidityLeeway time.Duration `mapstructure:"validity_leeway"`
}

func (s *SessionLifespanConfig) CreateSessionLifespan(rawData []byte) (*SessionLifespan, error) {
	activeValue := gjson.GetBytes(rawData, s.ActiveField)
	issuedAtValue := gjson.GetBytes(rawData, s.IssuedAtField)
	notBeforeValue := gjson.GetBytes(rawData, s.NotBeforeField)
	notAfterValue := gjson.GetBytes(rawData, s.NotAfterField)

	isActive := x.IfThenElseExec(activeValue.Exists(), activeValue.Bool, func() bool { return true })

	issuedAt, err := x.IfThenElseExecErr(issuedAtValue.Exists(),
		func() (time.Time, error) { return s.parseTime(issuedAtValue.String()) },
		func() (time.Time, error) { return time.Time{}, nil })
	if err != nil {
		return nil, errorchain.NewWithMessage(ErrSessionLifespanParseError,
			"failed parsing issued_at field").CausedBy(err)
	}

	notBefore, err := x.IfThenElseExecErr(notBeforeValue.Exists(),
		func() (time.Time, error) { return s.parseTime(notBeforeValue.String()) },
		func() (time.Time, error) { return time.Time{}, nil })
	if err != nil {
		return nil, errorchain.NewWithMessage(ErrSessionLifespanParseError,
			"failed parsing not_before field").CausedBy(err)
	}

	notAfter, err := x.IfThenElseExecErr(notAfterValue.Exists(),
		func() (time.Time, error) { return s.parseTime(notAfterValue.String()) },
		func() (time.Time, error) { return time.Time{}, nil })
	if err != nil {
		return nil, errorchain.NewWithMessage(ErrSessionLifespanParseError,
			"failed parsing not_after field").CausedBy(err)
	}

	return &SessionLifespan{
		active: isActive,
		iat:    issuedAt,
		nbf:    notBefore,
		exp:    notAfter,
		leeway: s.ValidityLeeway,
	}, nil
}

func (s *SessionLifespanConfig) parseTime(value string) (time.Time, error) {
	const (
		base10    = 10
		bitSize64 = 64
	)

	// if time format is not set, unix epoch time stamp is assumed
	if len(s.TimeFormat) == 0 {
		intVal, err := strconv.ParseInt(value, base10, bitSize64)
		if err != nil {
			return time.Time{}, err
		}

		return time.Unix(intVal, 0), nil
	}

	return time.Parse(s.TimeFormat, value)
}
