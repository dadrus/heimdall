package pipeline

type Rule interface {
	GetID() string
	// ReplaceAllString searches the input string and replaces each match (with the rule's pattern)
	// found with the replacement text.
}
