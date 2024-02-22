package cache

type Factory interface {
	Create(conf map[string]any) (Cache, error)
}

type FactoryFunc func(conf map[string]any) (Cache, error)

func (f FactoryFunc) Create(conf map[string]any) (Cache, error) {
	return f(conf)
}
