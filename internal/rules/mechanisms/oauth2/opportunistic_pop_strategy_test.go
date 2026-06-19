package oauth2

import (
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpportunisticPoPStrategyMerge(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		tbm         PoPStrategy
		expectOther bool
	}{
		"if tbm is nil, expect source strategy to be returned": {
			expectOther: false,
		},
		"if tbm is not nil, expect tbm to be returned": {
			tbm:         NewPoPStrategyMock(t),
			expectOther: true,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			strategy := opportunisticPoPStrategy{}

			// WHEN
			result := strategy.Merge(tc.tbm)

			// THEN
			if tc.expectOther {
				assert.Equal(t, tc.tbm, result)
			} else {
				assert.Equal(t, strategy, result)
			}
		})
	}
}

func TestOpportunisticPoPStrategyAssert(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		token  *Token
		expErr bool
	}{
		"successful if no cnf claim is present": {
			token:  &Token{},
			expErr: false,
		},
		"executes dpop strategy if jkt claim is present in the cnf claim": {
			token: &Token{
				Claims: Claims{
					Confirmation: &Confirmation{
						JWKThumbprint: "foo",
					},
				},
			},
			expErr: true,
		},
		"executes mtls strategy if x5t#S256 claim is present in the cnf claim": {
			token: &Token{
				Claims: Claims{Confirmation: &Confirmation{
					CertificateThumbprintSHA256: "foo",
				}},
			},
			expErr: false,
		},
		"successful if neither jkt, nor x5t#S256 claims are present in cnf": {
			token: &Token{
				Claims: Claims{Confirmation: &Confirmation{}},
			},
			expErr: false,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			strategy := opportunisticPoPStrategy{}

			err := strategy.Assert(nil, tc.token, 2*time.Second, []jose.SignatureAlgorithm{jose.ES256})

			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
