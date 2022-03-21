package config

// MatchingStrategy defines matching strategy such as Regexp or Glob.
// Empty string defaults to "regexp".
type MatchingStrategy string

// Possible matching strategies.
const (
	Regexp MatchingStrategy = "regexp"
	Glob   MatchingStrategy = "glob"
)
