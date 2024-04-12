package indextree

import (
	"slices"
	"strings"
)

type domainNode[V any] struct {
	// The full domain is stored here.
	fullDomain string

	// The domain part is stored here.
	domainPart string

	isLeaf bool

	priority int

	staticIndices  []byte
	staticChildren []*domainNode[V]

	wildcardChild *domainNode[V]
	isWildcard    bool

	pathRoot *pathNode[V]
}

func (n *domainNode[V]) findNode(domain string) *domainNode[V] {
	domainLen := len(domain)

	var found *domainNode[V]

	// only return a match if we're at a leaf node, this is to ensure that
	// we don't match on partial domains (e.g. com matching on example.com)
	if domainLen == 0 && n.isLeaf {
		return n
	} else if domainLen == 0 {
		return nil
	}

	token := domain[0]
	for i, index := range n.staticIndices {
		if token == index {
			child := n.staticChildren[i]
			childDomainLen := len(child.domainPart)

			if domainLen >= childDomainLen && child.domainPart == domain[:childDomainLen] {
				nextDomain := domain[childDomainLen:]
				found = child.findNode(nextDomain)
			}

			break
		}
	}

	if n.wildcardChild != nil && found == nil {
		// we don't iterate over periods so that we can match on multiple levels of subdomains
		found = n.wildcardChild
	}

	return found
}

func (n *domainNode[V]) find(domain string) *domainNode[V] {
	return n.findNode(reverseDomain(domain))
}

func (n *domainNode[V]) delEdge(token byte) {
	for i, index := range n.staticIndices {
		if token == index {
			n.staticChildren = append(n.staticChildren[:i], n.staticChildren[i+1:]...)
			n.staticIndices = append(n.staticIndices[:i], n.staticIndices[i+1:]...)

			return
		}
	}
}

func (n *domainNode[V]) delNode(domain string) bool {
	domainLen := len(domain)

	if domainLen == 0 {
		return n.isLeaf
	}

	firstChar := domain[0]
	if firstChar == '*' && n.wildcardChild != nil {
		n.deleteChild(n.wildcardChild, firstChar)

		return true
	}

	for i, staticIndex := range n.staticIndices {
		if firstChar == staticIndex {
			child := n.staticChildren[i]
			childDomainLen := len(child.domainPart)

			if domainLen >= childDomainLen && child.domainPart == domain[:childDomainLen] {
				nextToken := domain[childDomainLen:]
				if child.delNode(nextToken) {
					n.deleteChild(child, firstChar)

					return true
				}
			}

			break
		}
	}

	return false
}

func (n *domainNode[V]) deleteChild(child *domainNode[V], token uint8) {
	// Delete the child if it's a leaf node
	if child.isLeaf {
		child.isLeaf = false
	}

	if len(child.staticIndices) == 1 && child.staticIndices[0] != '.' && child.domainPart != "." {
		if len(child.staticChildren) == 1 {
			old := child.staticChildren[0]
			old.domainPart = child.domainPart + old.domainPart
			*child = *old
		}
	}

	if child.isLeaf {
		return
	}

	// Delete the child from the parent only if the child has no children
	if len(child.staticIndices) == 0 {
		n.delEdge(token)
	}

	// remove the wildcard child if it exists
	if child.isWildcard {
		n.wildcardChild = nil
	}
}

func (n *domainNode[V]) delete(domain string) bool {
	return n.delNode(reverseDomain(domain))
}

func (n *domainNode[V]) add(fullDomain string) *domainNode[V] {
	res := n.addNode(reverseDomain(fullDomain))

	res.fullDomain = fullDomain

	if res.pathRoot == nil {
		res.pathRoot = &pathNode[V]{}
	}

	return res
}

func (n *domainNode[V]) addNode(domain string) *domainNode[V] {
	// If the domain is empty, we're done.
	if len(domain) == 0 {
		n.isLeaf = true

		return n
	}

	token := domain[0]
	nextPeriod := strings.Index(domain, ".")

	var (
		thisToken string
		tokenEnd  int
	)

	switch {
	case token == '.':
		thisToken = "."
		tokenEnd = 1
	case nextPeriod == -1:
		thisToken = domain
		tokenEnd = len(domain)
	default:
		thisToken = domain[0:nextPeriod]
		tokenEnd = nextPeriod
	}

	remainingDomain := domain[tokenEnd:]

	if token == '*' {
		if n.wildcardChild == nil {
			n.wildcardChild = &domainNode[V]{
				domainPart: thisToken,
				isWildcard: true,
				isLeaf:     true,
			}
		}

		return n.wildcardChild
	}

	// Do we have an existing node that starts with the same letter?
	for i, index := range n.staticIndices {
		if token == index {
			child, prefixSplit := n.splitCommonDomainPrefix(i, thisToken)

			child.priority++

			n.sortStaticChild(i)

			return child.addNode(domain[prefixSplit:])
		}
	}

	// No existing node starting with this letter, so create it.
	child := &domainNode[V]{domainPart: thisToken}

	n.staticIndices = append(n.staticIndices, token)
	n.staticChildren = append(n.staticChildren, child)

	return child.addNode(remainingDomain)
}

func (n *domainNode[V]) sortStaticChild(i int) {
	for i > 0 && n.staticChildren[i].priority > n.staticChildren[i-1].priority {
		n.staticChildren[i], n.staticChildren[i-1] = n.staticChildren[i-1], n.staticChildren[i]
		n.staticIndices[i], n.staticIndices[i-1] = n.staticIndices[i-1], n.staticIndices[i]
		i--
	}
}

func (n *domainNode[V]) splitCommonDomainPrefix(existingNodeIndex int, domain string) (*domainNode[V], int) {
	childNode := n.staticChildren[existingNodeIndex]

	if strings.HasPrefix(domain, childNode.domainPart) {
		// No split needs to be done. Rather, the new path shares the entire
		// prefix with the existing node, so the new node is just a child of
		// the existing one. Or the new path is the same as the existing path,
		// which means that we just move on to the next token. Either way,
		// this return accomplishes that
		return childNode, len(childNode.domainPart)
	}

	var i int
	// Find the length of the common prefix of the child node and the new path.
	for i = range childNode.domainPart {
		if i == len(domain) {
			break
		}

		if domain[i] != childNode.domainPart[i] {
			break
		}
	}

	commonPrefix := domain[0:i]
	childNode.domainPart = childNode.domainPart[i:]

	// Create a new intermediary node in the place of the existing node, with
	// the existing node as a child.
	newNode := &domainNode[V]{
		domainPart: commonPrefix,
		priority:   childNode.priority,
		// Index is the first letter of the non-common part of the path.
		staticIndices:  []byte{childNode.domainPart[0]},
		staticChildren: []*domainNode[V]{childNode},
	}
	n.staticChildren[existingNodeIndex] = newNode

	return newNode, i
}

// reverseDomain returns the reverse octets of the given domain.
func reverseDomain(domain string) string {
	domainSlice := strings.Split(domain, ".")
	slices.Reverse(domainSlice)

	return strings.Join(domainSlice, ".")
}
