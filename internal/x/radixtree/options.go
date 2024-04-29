package radixtree

type Option[V any] func(n *Tree[V])

func WithValuesConstraints[V any](constraints ConstraintsFunc[V]) Option[V] {
	return func(n *Tree[V]) {
		if constraints != nil {
			n.canAdd = constraints
		}
	}
}

type AddOption[V any] func(n *Tree[V])

func WithBacktracking[V any](flag bool) AddOption[V] {
	return func(n *Tree[V]) {
		n.backtrackingEnabled = flag
	}
}
