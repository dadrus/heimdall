package radixtree

type Entry[V any] struct {
	Value      V
	Parameters map[string]string
}

type IndexTree[V any] interface {
	Add(path string, value V) error
	Find(path string, matcher Matcher[V]) (*Entry[V], error)
	Delete(path string, matcher Matcher[V]) error
	Update(path string, value V, matcher Matcher[V]) error
	Empty() bool
}

func New[V any](opts ...Option[V]) IndexTree[V] {
	root := &node[V]{
		canAdd: func(_ []V, _ V) bool { return true },
	}

	for _, opt := range opts {
		opt(root)
	}

	return root
}
