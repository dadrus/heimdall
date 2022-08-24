package authenticators

import (
	"errors"
	"time"

	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var ErrSessionValidity = errors.New("session validity error")

const defaultLeeway = 10 * time.Second

type Session struct {
	active bool
	iat    time.Time
	nbf    time.Time
	naf    time.Time
	leeway time.Duration
}

func (v *Session) Assert() error {
	if !v.active {
		return errorchain.NewWithMessage(ErrSessionValidity, "not active")
	}

	if err := v.assertValidity(); err != nil {
		return err
	}

	return v.assertIssuanceTime()
}

func (v *Session) assertValidity() error {
	leeway := int64(x.IfThenElse(v.leeway != 0, v.leeway, defaultLeeway).Seconds())
	now := time.Now().Unix()
	nbf := v.nbf.Unix()
	exp := v.naf.Unix()

	if nbf > 0 && now+leeway < nbf {
		return errorchain.NewWithMessage(ErrSessionValidity, "not yet valid")
	}

	if exp > 0 && now-leeway >= exp {
		return errorchain.NewWithMessage(ErrSessionValidity, "expired")
	}

	return nil
}

func (v *Session) assertIssuanceTime() error {
	leeway := x.IfThenElse(v.leeway != 0, v.leeway, defaultLeeway)

	// IssuedAt is optional but cannot be in the future. This is not required by the RFC, but
	// if by misconfiguration it has been set to future, we don't trust it.
	if !v.iat.Equal(time.Time{}) && time.Now().Add(leeway).Before(v.iat) {
		return errorchain.NewWithMessage(ErrSessionValidity, "issued in the future")
	}

	return nil
}
