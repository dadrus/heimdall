// Copyright 2024 Dimitrij Drus <dadrus@gmx.de>
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

package tlsx

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestKeyStoreCertificate(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc       string
		config   func(t *testing.T, ccm *compatibilityCheckerMock)
		expError bool
	}{
		{
			uc:       "fails",
			expError: true,
			config: func(t *testing.T, ccm *compatibilityCheckerMock) {
				t.Helper()

				ccm.EXPECT().SupportsCertificate(mock.Anything).Return(errors.New("test error"))
			},
		},
		{
			uc: "succeed",
			config: func(t *testing.T, ccm *compatibilityCheckerMock) {
				t.Helper()

				ccm.EXPECT().SupportsCertificate(mock.Anything).Return(nil)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			ks := &keyStore{}

			ccm := newCompatibilityCheckerMock(t)
			tc.config(t, ccm)

			// WHEN
			_, err := ks.certificate(ccm)

			// THEN
			if tc.expError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			ccm.AssertExpectations(t)
		})
	}
}

func TestKeyStoreOnChanged(t *testing.T) {
	t.Parallel()
}
