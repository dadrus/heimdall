// Copyright 2022 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package patternmatcher

import (
	"bytes"
	"errors"

	"github.com/gobwas/glob"
)

var (
	ErrUnbalancedPattern    = errors.New("unbalanced pattern")
	ErrNoGlobPatternDefined = errors.New("no glob pattern defined")
)

type globMatcher struct {
	compiled glob.Glob
}

func (m *globMatcher) Match(value string) bool {
	return m.compiled.Match(value)
}

func newGlobMatcher(pattern string) (*globMatcher, error) {
	if len(pattern) == 0 {
		return nil, ErrNoGlobPatternDefined
	}

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

	for ind := range len(value) {
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
