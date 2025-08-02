package radixtrie

type wildcardLookupStrategy[V any] struct{}

func (s wildcardLookupStrategy[V]) lookupNodes(trie *Trie[V], hostPattern, pathPattern string) ([]*Trie[V], error) {
	var (
		tokens     string
		separator  byte
		isHostPart bool

		nextTokens string
		child      *Trie[V]
	)

	// Determine which part we're processing and get the appropriate string and separator
	if len(hostPattern) != 0 {
		tokens = hostPattern
		separator = '.'
		isHostPart = true
	} else {
		tokens = pathPattern
		separator = '/'
		isHostPart = false
	}

	if len(tokens) == 0 {
		return []*Trie[V]{trie}, nil
	}

	// First see if this matches a static token.
	token := tokens[0]
	for i, staticIndex := range trie.staticIndices {
		if token == staticIndex { //nolint: nestif
			child = trie.staticChildren[i]
			childTokenLen := len(child.token)

			if len(tokens) >= childTokenLen && child.token == tokens[:childTokenLen] {
				if isHostPart {
					return s.lookupNodes(child, tokens[childTokenLen:], pathPattern)
				}

				return s.lookupNodes(child, "", tokens[childTokenLen:])
			}

			break
		}
	}

	if len(trie.token) == 0 || trie.token == string(separator) {
		switch token {
		case ':':
			// Only valid for paths
			if isHostPart {
				return nil, ErrNotFound
			}

			nextSeparator := trie.nextSeparator(tokens, separator)
			nextTokens = tokens[nextSeparator:]

			if trie.wildcardChild != nil {
				child = trie.wildcardChild
			} else {
				var nodes []*Trie[V]
				for _, node := range trie.staticChildren {
					_, err := s.lookupNodes(node, "", nextTokens)
					if err == nil {
						nodes = append(nodes, node)
					}
				}

				if len(nodes) != 0 {
					return nodes, nil
				}
			}
		case '*':
			nextTokens = ""

			if trie.catchAllChild != nil {
				child = trie.catchAllChild
			} else {
				return trie.staticChildren, nil
			}
		}
	}

	if child != nil {
		if isHostPart {
			return s.lookupNodes(child, nextTokens, pathPattern)
		}

		return s.lookupNodes(child, "", nextTokens)
	}

	if !isHostPart && trie.wildcardChild != nil { //nolint:nestif
		// Didn't find a static token, so check for a wildcard (only for paths).
		nextSeparator := trie.nextSeparator(tokens, separator)
		thisToken := tokens[0:nextSeparator]
		nextToken := tokens[nextSeparator:]

		if len(thisToken) > 0 { // Don't match on empty tokens.
			return s.lookupNodes(trie.wildcardChild, "", nextToken)
		}
	}

	if trie.catchAllChild != nil {
		if isHostPart {
			// Transit to path part
			return s.lookupNodes(trie.catchAllChild, "", pathPattern)
		}

		return s.lookupNodes(trie.catchAllChild, "", "")
	}

	return nil, ErrNotFound
}
