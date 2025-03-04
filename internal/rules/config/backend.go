// Copyright 2023 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"net/url"
)

type Backend struct {
	Host              string       `json:"host"                yaml:"host"             validate:"required"` //nolint:tagalign
	ForwardHostHeader *bool        `json:"forward_host_header" yaml:"forward_host_header"`
	URLRewriter       *URLRewriter `json:"rewrite"             yaml:"rewrite"          validate:"omitnil"` //nolint:tagalign
}

func (b *Backend) CreateURL(value *url.URL) *url.URL {
	upstreamURL := &url.URL{
		Scheme:   value.Scheme,
		Host:     b.Host,
		Path:     value.Path,
		RawPath:  value.RawPath,
		RawQuery: value.RawQuery,
	}

	if b.URLRewriter != nil {
		b.URLRewriter.Rewrite(upstreamURL)
	}

	return upstreamURL
}

func (b *Backend) DeepCopyInto(out *Backend) {
	*out = *b

	if b.ForwardHostHeader != nil {
		in, out := &b.ForwardHostHeader, &out.ForwardHostHeader
		*out = new(bool)
		**out = **in
	}

	if b.URLRewriter != nil {
		b.URLRewriter.DeepCopyInto(out.URLRewriter)
	}
}

func (b *Backend) IsInsecure() bool {
	return b != nil && b.URLRewriter != nil && b.URLRewriter.Scheme == "http"
}
