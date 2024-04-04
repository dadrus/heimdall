package subject

import (
	"crypto/sha256"

	"github.com/dadrus/heimdall/internal/x/stringx"
)

type Subject map[string]*Principal

func (s Subject) Hash() []byte {
	hash := sha256.New()

	for name, principal := range s {
		hash.Write(stringx.ToBytes(name))
		hash.Write(principal.Hash())
	}

	return hash.Sum(nil)
}

func (s Subject) AddPrincipal(id string, principal *Principal) {
	s[id] = principal
}
