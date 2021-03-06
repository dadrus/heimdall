package patternmatcher

import (
	"bytes"
	"errors"

	"github.com/gobwas/glob"
)

var ErrUnbalancedPattern = errors.New("unbalanced pattern")

type globMatcher struct {
	compiled glob.Glob
}

func (m *globMatcher) Match(value string) bool {
	return m.compiled.Match(value)
}

func newGlobMatcher(pattern string) (*globMatcher, error) {
	compiled, err := compileGlob(pattern, '<', '>')
	if err != nil {
		return nil, err
	}

	return &globMatcher{compiled: compiled}, nil
}

func compileGlob(pattern string, delimiterStart, delimiterEnd rune) (glob.Glob, error) {
	// Check if it is well-formed.
	idxs, errBraces := delimiterIndices(pattern, delimiterStart, delimiterEnd)
	if errBraces != nil {
		return nil, errBraces
	}

	buffer := bytes.NewBufferString("")

	var end int
	for ind := 0; ind < len(idxs); ind += 2 {
		// Set all values we are interested in.
		raw := pattern[end:idxs[ind]]
		end = idxs[ind+1]
		patt := pattern[idxs[ind]+1 : end-1]

		buffer.WriteString(glob.QuoteMeta(raw))
		buffer.WriteString(patt)
	}

	// Add the remaining.
	raw := pattern[end:]
	buffer.WriteString(glob.QuoteMeta(raw))

	// Compile full regexp.
	return glob.Compile(buffer.String(), '.', '/')
}

// delimiterIndices returns the first level delimiter indices from a string.
// It returns an error in case of unbalanced delimiters.
func delimiterIndices(value string, delimiterStart, delimiterEnd rune) ([]int, error) {
	var level, idx int

	idxs := make([]int, 0)

	for ind := 0; ind < len(value); ind++ {
		switch value[ind] {
		case byte(delimiterStart):
			if level++; level == 1 {
				idx = ind
			}
		case byte(delimiterEnd):
			if level--; level == 0 {
				idxs = append(idxs, idx, ind+1)
			} else if level < 0 {
				return nil, ErrUnbalancedPattern
			}
		}
	}

	if level != 0 {
		return nil, ErrUnbalancedPattern
	}

	return idxs, nil
}
