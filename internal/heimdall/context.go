package heimdall

import (
	"context"
	"net/url"
)

type Context interface {
	RequestMethod() string
	RequestHeaders() map[string]string
	RequestHeader(key string) string
	RequestCookie(key string) string
	RequestQueryParameter(key string) string
	RequestFormParameter(key string) string
	RequestBody() []byte
	RequestURL() *url.URL
	RequestClientIPs() []string

	AddHeaderForUpstream(name, value string)
	AddCookieForUpstream(name, value string)

	AppContext() context.Context

	SetPipelineError(err error)

	Signer() JWTSigner
}
