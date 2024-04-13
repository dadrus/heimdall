package indextree

func NewIndexTree[V any]() *IndexTree[V] {
	return &IndexTree[V]{tree: &domainNode[V]{}}
}

type IndexTree[V any] struct {
	tree *domainNode[V]
}

func (t *IndexTree[V]) Add(domain, path string, value V) error {
	return t.tree.add(domain).pathRoot.add(path, value)
}

func (t *IndexTree[V]) Find(domain, path string, matcher Matcher[V]) (V, map[string]string, error) {
	var def V

	dn := t.tree.find(domain)
	if dn == nil {
		return def, nil, ErrNotFound
	}

	return dn.pathRoot.find(path, matcher)
}

func (t *IndexTree[V]) Delete(domain, path string, matcher Matcher[V]) error {
	dn := t.tree.find(domain)
	if dn == nil {
		return ErrNotFound
	}

	if !dn.pathRoot.delete(path, matcher) {
		return ErrFailedToDelete
	}

	if dn.pathRoot.empty() && !t.tree.delete(domain) {
		return ErrFailedToDelete
	}

	return nil
}
