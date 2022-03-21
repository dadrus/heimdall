package pipeline

import (
	"github.com/dadrus/heimdall/config"
)

type Rule interface {
	GetID() string
	// ReplaceAllString searches the input string and replaces each match (with the rule's pattern)
	// found with the replacement text.
	ReplaceAllString(strategy config.MatchingStrategy, input, replacement string) (string, error)
}
