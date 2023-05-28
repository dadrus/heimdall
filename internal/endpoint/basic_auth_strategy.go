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

package endpoint

import (
	"context"
	"crypto/sha256"
	"net/http"

	"github.com/dadrus/heimdall/internal/x/stringx"
)

type BasicAuthStrategy struct {
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
}

func (c *BasicAuthStrategy) Apply(_ context.Context, req *http.Request) error {
	req.SetBasicAuth(c.User, c.Password)

	return nil
}

func (c *BasicAuthStrategy) Hash() []byte {
	hash := sha256.New()

	hash.Write(stringx.ToBytes(c.User))
	hash.Write(stringx.ToBytes(c.Password))

	return hash.Sum(nil)
}
