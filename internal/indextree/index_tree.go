package indextree

func NewIndexTree[V any]() *IndexTree[V] {
	return &IndexTree[V]{tree: &node[V]{}}
}

type IndexTree[V any] struct {
	tree *node[V]
}

func (t *IndexTree[V]) Add(path string, value V) error {
	return t.tree.Add(path, value)
}

func (t *IndexTree[V]) Find(path string, matcher Matcher[V]) (V, map[string]string, error) {
	return t.tree.Find(path, matcher)
}

func (t *IndexTree[V]) Delete(path string, matcher Matcher[V]) error {
	if !t.tree.Delete(path, matcher) {
		return ErrFailedToDelete
	}

	return nil
}

func (t *IndexTree[V]) Update(path string, value V, matcher Matcher[V]) error {
	if !t.tree.Update(path, value, matcher) {
		return ErrFailedToUpdate
	}

	return nil
}

func (t *IndexTree[V]) Empty() bool { return t.tree.Empty() }
