package config

import (
	"net/url"

	"github.com/goccy/go-json"
)

type UpstreamURLFactory struct {
	Host        string       `json:"host" yaml:"host"`
	URLRewriter *URLRewriter `json:"rewrite" yaml:"rewrite"`
}

func (f *UpstreamURLFactory) CreateURL(value *url.URL) *url.URL {
	upstreamURL := &url.URL{
		Scheme:   value.Scheme,
		Host:     f.Host,
		Path:     value.Path,
		RawQuery: value.RawQuery,
	}

	if f.URLRewriter != nil {
		return f.URLRewriter.Rewrite(upstreamURL)
	}

	return upstreamURL
}

func (f *UpstreamURLFactory) DeepCopyInto(out *UpstreamURLFactory) {
	if f == nil {
		return
	}

	jsonStr, _ := json.Marshal(f)

	// we cannot do anything with an error here as
	// the interface implemented here doesn't support
	// error responses
	json.Unmarshal(jsonStr, out) //nolint:errcheck
}
