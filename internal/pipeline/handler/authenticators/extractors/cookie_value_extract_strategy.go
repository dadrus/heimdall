package extractors

import (
	"net/http"
	"strings"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type CookieValueExtractStrategy struct {
	Name string
}

func (es CookieValueExtractStrategy) GetAuthData(s heimdall.Context) (AuthData, error) {
	if val := s.RequestCookie(es.Name); len(val) != 0 {
		return &cookieAuthData{
			name:  es.Name,
			value: strings.TrimSpace(val),
		}, nil
	}

	return nil, errorchain.NewWithMessagef(ErrAuthData, "no '%s' cookie present", es.Name)
}

type cookieAuthData struct {
	name  string
	value string
}

func (c *cookieAuthData) ApplyTo(req *http.Request) {
	req.AddCookie(&http.Cookie{Name: c.name, Value: c.value})
}

func (c *cookieAuthData) Value() string {
	return c.value
}
