package secrets2

import (
	"errors"

	"github.com/dadrus/heimdall/internal/secrets2/types"
)

var (
	ErrSourceForbidden           = errors.New("secret source forbidden")
	ErrSecretConversionFailed    = errors.New("secret conversion failed")
	ErrResolverScopeClosed       = errors.New("secret resolver scope closed")
	ErrUnsupportedProviderType   = types.ErrUnsupportedProviderType
	ErrSecretNotFound            = types.ErrSecretNotFound
	ErrSecretSetNotFound         = types.ErrSecretSetNotFound
	ErrCredentialsNotFound       = types.ErrCredentialsNotFound
	ErrCertificateBundleNotFound = types.ErrCertificateBundleNotFound
	ErrInvalidCredentialsPayload = types.ErrInvalidCredentialsPayload
	ErrSourceNotFound            = types.ErrSourceNotFound
	ErrDependencyNotDeclared     = types.ErrDependencyNotDeclared
	ErrUnsupportedOperation      = types.ErrUnsupportedOperation
	ErrConfiguration             = types.ErrConfiguration
	ErrInternal                  = types.ErrInternal
)
