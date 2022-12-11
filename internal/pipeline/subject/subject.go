package subject

import (
	"crypto/sha256"

	"github.com/goccy/go-json"
)

type Subject struct {
	ID         string         `json:"id"`
	Attributes map[string]any `json:"attributes"`
}

func (s *Subject) Hash() []byte {
	hash := sha256.New()
	rawSub, _ := json.Marshal(s)

	hash.Write(rawSub)

	return hash.Sum(nil)
}
