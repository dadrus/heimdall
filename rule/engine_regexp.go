package rule

import (
	"bytes"
	"errors"
	"fmt"
	"hash/crc64"
	"regexp"
	"time"

	"github.com/dlclark/regexp2"
)

const regexp2MatchTimeout = time.Millisecond * 250

func NewRegexEngine() MatchingEngine {
	e := new(regexpMatchingEngine)
	e.table = crc64.MakeTable(polynomial)
	return e
}

type regexpMatchingEngine struct {
	compiled *regexp2.Regexp
	checksum uint64
	table    *crc64.Table
}

func (re *regexpMatchingEngine) compile(pattern string) error {
	if checksum := crc64.Checksum([]byte(pattern), re.table); checksum != re.checksum {
		compiled, err := re.compileRegex(pattern, '<', '>')
		if err != nil {
			return err
		}
		re.compiled = compiled
		re.checksum = checksum
	}
	return nil
}

// Checksum of a saved pattern.
func (re *regexpMatchingEngine) Checksum() uint64 {
	return re.checksum
}

// IsMatching determines whether the input matches the pattern.
func (re *regexpMatchingEngine) IsMatching(pattern, matchAgainst string) (bool, error) {
	if err := re.compile(pattern); err != nil {
		return false, err
	}
	return re.compiled.MatchString(matchAgainst)
}

// ReplaceAllString replaces all matches in `input` with `replacement`.
func (re *regexpMatchingEngine) ReplaceAllString(pattern, input, replacement string) (string, error) {
	if err := re.compile(pattern); err != nil {
		return "", err
	}
	return re.compiled.Replace(input, replacement, -1, -1)
}

// FindStringSubmatch returns all captures in matchAgainst following the pattern
func (re *regexpMatchingEngine) FindStringSubmatch(pattern, matchAgainst string) ([]string, error) {
	if err := re.compile(pattern); err != nil {
		return nil, err
	}

	m, _ := re.compiled.FindStringMatch(matchAgainst)
	if m == nil {
		return nil, errors.New("not match")
	}

	var result []string
	for _, group := range m.Groups()[1:] {
		result = append(result, group.String())
	}

	return result, nil
}

// delimiterIndices returns the first level delimiter indices from a string.
// It returns an error in case of unbalanced delimiters.
func (re *regexpMatchingEngine) delimiterIndices(s string, delimiterStart, delimiterEnd byte) ([]int, error) {
	var level, idx int
	idxs := make([]int, 0)
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case delimiterStart:
			if level++; level == 1 {
				idx = i
			}
		case delimiterEnd:
			if level--; level == 0 {
				idxs = append(idxs, idx, i+1)
			} else if level < 0 {
				return nil, fmt.Errorf(`Unbalanced braces in "%q"`, s)
			}
		}
	}

	if level != 0 {
		return nil, fmt.Errorf(`Unbalanced braces in "%q"`, s)
	}

	return idxs, nil
}

// CompileRegex parses a template and returns a Regexp.
//
// You can define your own delimiters. It is e.g. common to use curly braces {} but I recommend using characters
// which have no special meaning in Regex, e.g.: <, >
//
//  reg, err := compiler.CompileRegex("foo:bar.baz:<[0-9]{2,10}>", '<', '>')
//  // if err != nil ...
//  reg.MatchString("foo:bar.baz:123")
func (re *regexpMatchingEngine) compileRegex(tpl string, delimiterStart, delimiterEnd byte) (*regexp2.Regexp, error) {
	// Check if it is well-formed.
	idxs, errBraces := re.delimiterIndices(tpl, delimiterStart, delimiterEnd)
	if errBraces != nil {
		return nil, errBraces
	}
	varsR := make([]*regexp2.Regexp, len(idxs)/2)
	pattern := bytes.NewBufferString("")
	pattern.WriteByte('^')

	var end int
	for i := 0; i < len(idxs); i += 2 {
		// Set all values we are interested in.
		raw := tpl[end:idxs[i]]
		end = idxs[i+1]
		patt := tpl[idxs[i]+1 : end-1]
		// Build the regexp pattern.
		varIdx := i / 2
		fmt.Fprintf(pattern, "%s(%s)", regexp.QuoteMeta(raw), patt)
		reg, err := regexp2.Compile(fmt.Sprintf("^%s$", patt), regexp2.RE2)
		if err != nil {
			return nil, err
		}
		reg.MatchTimeout = regexp2MatchTimeout
		varsR[varIdx] = reg
	}

	// Add the remaining.
	raw := tpl[end:]
	pattern.WriteString(regexp.QuoteMeta(raw))
	pattern.WriteByte('$')

	// Compile full regexp.
	reg, errCompile := regexp2.Compile(pattern.String(), regexp2.RE2)
	if errCompile != nil {
		return nil, errCompile
	}
	reg.MatchTimeout = regexp2MatchTimeout

	return reg, nil
}
