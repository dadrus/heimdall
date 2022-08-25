package authenticators

import (
	"strconv"
	"time"

	"github.com/tidwall/gjson"

	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type SessionConfig struct {
	ActiveField    string        `mapstructure:"active"`
	IssuedAtField  string        `mapstructure:"issued_at"`
	NotBeforeField string        `mapstructure:"not_before"`
	NotAfterField  string        `mapstructure:"not_after"`
	TimeFormat     string        `mapstructure:"time_format"`
	ValidityLeeway time.Duration `mapstructure:"validity_leeway"`
}

func (vc *SessionConfig) CreateSession(rawData []byte) (*Session, error) {
	activeValue := gjson.GetBytes(rawData, vc.ActiveField)
	issuedAtValue := gjson.GetBytes(rawData, vc.IssuedAtField)
	notBeforeValue := gjson.GetBytes(rawData, vc.NotBeforeField)
	notAfterValue := gjson.GetBytes(rawData, vc.NotAfterField)

	isActive := x.IfThenElseExec(activeValue.Exists(), activeValue.Bool, func() bool { return true })

	issuedAt, err := x.IfThenElseExecErr(issuedAtValue.Exists(),
		func() (time.Time, error) { return vc.parseTime(issuedAtValue.String()) },
		func() (time.Time, error) { return time.Time{}, nil })
	if err != nil {
		return nil, errorchain.NewWithMessage(ErrSessionValidity,
			"failed parsing issued_at field").CausedBy(err)
	}

	notBefore, err := x.IfThenElseExecErr(notBeforeValue.Exists(),
		func() (time.Time, error) { return vc.parseTime(notBeforeValue.String()) },
		func() (time.Time, error) { return time.Time{}, nil })
	if err != nil {
		return nil, errorchain.NewWithMessage(ErrSessionValidity,
			"failed parsing not_before field").CausedBy(err)
	}

	notAfter, err := x.IfThenElseExecErr(notAfterValue.Exists(),
		func() (time.Time, error) { return vc.parseTime(notAfterValue.String()) },
		func() (time.Time, error) { return time.Time{}, nil })
	if err != nil {
		return nil, errorchain.NewWithMessage(ErrSessionValidity,
			"failed parsing not_after field").CausedBy(err)
	}

	return &Session{
		active: isActive,
		iat:    issuedAt,
		nbf:    notBefore,
		naf:    notAfter,
		leeway: vc.ValidityLeeway,
	}, nil
}

func (vc *SessionConfig) parseTime(value string) (time.Time, error) {
	const (
		base10    = 10
		bitSize64 = 64
	)

	// if time format is not set, unix epoch time stamp is assumed
	if len(vc.TimeFormat) == 0 {
		intVal, err := strconv.ParseInt(value, base10, bitSize64)
		if err != nil {
			return time.Time{}, err
		}

		return time.Unix(intVal, 0), nil
	}

	return time.Parse(vc.TimeFormat, value)
}
