package cache

type Factory interface {
	Create(conf map[string]any) (Cache, error)
}
