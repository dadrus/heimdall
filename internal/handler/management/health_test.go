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

package management

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/config"
)

func TestHealthRequest(t *testing.T) {
	t.Parallel()

	// GIVEN
	app := newApp(appArgs{
		Config:     &config.Configuration{Serve: config.ServeConfig{Management: config.ServiceConfig{}}},
		Registerer: prometheus.NewRegistry(),
		Logger:     log.Logger,
	})

	_, err := newHandler(handlerArgs{
		App:    app,
		Logger: log.Logger,
	})
	require.NoError(t, err)

	// WHEN
	resp, err := app.Test(
		httptest.NewRequest(http.MethodGet, "http://heimdall.test.local/.well-known/health", nil),
		-1)

	// THEN
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	defer resp.Body.Close()

	rawResp, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.JSONEq(t, `{ "status": "ok"}`, string(rawResp))
}
