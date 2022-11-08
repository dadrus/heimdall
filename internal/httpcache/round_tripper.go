package httpcache

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/pquerna/cachecontrol"

	"github.com/dadrus/heimdall/internal/cache"
)

var (
	ErrInvalidCacheEntry = errors.New("invalid cache entry")
	ErrNoCacheEntry      = errors.New("no cache entry")
)

type RoundTripper struct {
	Transport http.RoundTripper
}

func (rt *RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := rt.cachedResponse(req)
	if err == nil {
		return resp, nil
	}

	resp, err = rt.Transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	rt.cacheResponse(req, resp)

	return resp, nil
}

func (rt *RoundTripper) cachedResponse(req *http.Request) (*http.Response, error) {
	cch := cache.Ctx(req.Context())

	cachedValue := cch.Get(cacheKey(req))
	if cachedValue == nil {
		return nil, ErrNoCacheEntry
	}

	respDump, ok := cachedValue.([]byte)
	if !ok {
		return nil, ErrInvalidCacheEntry
	}

	return http.ReadResponse(bufio.NewReader(bytes.NewReader(respDump)), req)
}

func (rt *RoundTripper) cacheResponse(req *http.Request, resp *http.Response) {
	defaultExpirationTime := time.Time{}

	reasons, expires, err := cachecontrol.CachableResponse(req, resp, cachecontrol.Options{PrivateCache: true})
	if err != nil || len(reasons) != 0 || expires == defaultExpirationTime {
		return
	}

	respDump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		return
	}

	cch := cache.Ctx(req.Context())
	cch.Set(cacheKey(req), respDump, time.Until(expires))
}

func cacheKey(req *http.Request) string {
	hash := sha256.New()

	hash.Write([]byte("RFC 7234"))
	hash.Write([]byte(req.URL.String()))
	hash.Write([]byte(req.Method))

	value := req.Header.Get("Authorization")
	if len(value) != 0 {
		hash.Write([]byte(strings.TrimSpace(value)))
	}

	return hex.EncodeToString(hash.Sum(nil))
}
