package oauth2

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
)

func TestServerMetadataVerifyIssuer(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		metadataURL string
		issuer      string
		matching    bool
	}{
		{
			metadataURL: "https://example.com/issuer1/.well-known/openid-configuration",
			issuer:      "https://example.com/issuer1",
			matching:    true,
		},
		{
			metadataURL: "https://example.com/realms/issuer1/.well-known/openid-configuration",
			issuer:      "https://example.com/realms/issuer1",
			matching:    true,
		},
		{
			metadataURL: "https://example.com/.well-known/openid-configuration",
			issuer:      "https://example.com",
			matching:    true,
		},
		{
			metadataURL: "https://example.com/.well-known/openid-configuration/issuer1",
			issuer:      "https://example.com/issuer1",
			matching:    true,
		},
		{
			metadataURL: "https://example.com/.well-known/oauth-authorization-server/issuer1",
			issuer:      "https://example.com/issuer1",
			matching:    true,
		},
		{
			metadataURL: "https://example.com/.well-known/oauth-authorization-server",
			issuer:      "https://example.com",
			matching:    true,
		},
		{
			metadataURL: "https://example.com/.well-known/example-configuration",
			issuer:      "https://example.com",
			matching:    true,
		},
		{
			metadataURL: "https://example.com/.well-known/example-configuration/",
			issuer:      "https://example.com",
			matching:    true,
		},
		{
			metadataURL: "https://example.com/.well-known/example-configuration/issuer1",
			issuer:      "https://example.com/issuer1",
			matching:    true,
		},
		{
			metadataURL: "https://example.com/.well-known/example-configuration/issuer1/",
			issuer:      "https://example.com/issuer1",
			matching:    true,
		},
		{
			metadataURL: "https://example.com/example-configuration/issuer1/",
			issuer:      "https://example.com/example-configuration/issuer1",
			matching:    true,
		},
		{
			metadataURL: "https://example.com/example-configuration/issuer1",
			issuer:      "https://example.com",
			matching:    false,
		},
	} {
		t.Run(tc.metadataURL, func(t *testing.T) {
			// GIVEN
			sm := ServerMetadata{Issuer: tc.issuer}

			// WHEN
			err := sm.verify(tc.metadataURL)

			// THEN
			if tc.matching {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
			}
		})
	}
}
