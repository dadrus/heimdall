package oauth2

import (
	"fmt"
	"strings"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/endpoint"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type ServerMetadata struct {
	Issuer                string
	JWKSEndpoint          *endpoint.Endpoint
	IntrospectionEndpoint *endpoint.Endpoint
}

func (sm ServerMetadata) verify(usedMetadataURL string) error {
	var (
		expectedIssuer string
		uriPrefix      string
		uriSuffix      string
	)

	parts := strings.Split(usedMetadataURL, ".well-known/")
	uriPrefix = parts[0]

	if len(parts) > 1 {
		// this is actually not compliant, but there are corresponding implementations out there in the wild
		uriSuffix = strings.TrimSuffix(parts[1], "/")
	}

	if strings.Contains(uriSuffix, "/") {
		expectedIssuer = fmt.Sprintf("%s%s", uriPrefix, strings.Split(uriSuffix, "/")[1])
	} else {
		expectedIssuer = strings.TrimSuffix(uriPrefix, "/")
	}

	if sm.Issuer != expectedIssuer && sm.Issuer != expectedIssuer+"/" {
		return errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"expected issuer '%s' does not match issuer '%s' from the received metadata",
			expectedIssuer, sm.Issuer)
	}

	return nil
}
