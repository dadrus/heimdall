// Copyright 2022 Dimitrij Drus <dadrus@gmx.de>
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

package authstrategy

import (
	"context"
	"crypto/sha256"
	"net/http"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

type APIKey struct {
	In    string `mapstructure:"in"    validate:"required,oneof=cookie header query"`
	Name  string `mapstructure:"name"  validate:"required"`
	Value string `mapstructure:"value" validate:"required"`
}

func (c *APIKey) Apply(_ context.Context, req *http.Request) error {
	switch c.In {
	case "cookie":
		req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	case "header":
		req.Header.Set(c.Name, c.Value)
	case "query":
		query := req.URL.Query()
		query.Set(c.Name, c.Value)
		req.URL.RawQuery = query.Encode()
	default:
		return errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"unsupported in value (%s) in api key auth strategy", c.In)
	}

	return nil
}

func (c *APIKey) Hash() []byte {
	hash := sha256.New()

	hash.Write(stringx.ToBytes(c.In))
	hash.Write(stringx.ToBytes(c.Name))
	hash.Write(stringx.ToBytes(c.Value))

	return hash.Sum(nil)
}
