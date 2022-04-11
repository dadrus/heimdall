package heimdall

import (
	"context"
	"net/url"
)

type Context interface {
	RequestHeader(key string) string
	RequestCookie(key string) string
	RequestQueryParameter(key string) string
	RequestFormParameter(key string) string
	RequestBody() []byte
	RequestURL() *url.URL
	RequestClientIPs() []string

	AddResponseHeader(name, value string)
	AddResponseCookie(name, value string)

	AppContext() context.Context

	SetPipelineError(err error)

	Signer() JWTSigner
}
