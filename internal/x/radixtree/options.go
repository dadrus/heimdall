package radixtree

type Option[V any] func(n *node[V])

func WithValuesConstraints[V any](constraints ConstraintsFunc[V]) Option[V] {
	return func(n *node[V]) {
		if constraints != nil {
			n.canAdd = constraints
		}
	}
}
