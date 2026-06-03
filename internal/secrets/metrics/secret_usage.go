package metrics

import secrettypes "github.com/dadrus/heimdall/internal/secrets/types"

type SecretUsage interface {
	Track(secret secrettypes.Secret)
	Untrack(secret secrettypes.Secret)
}
