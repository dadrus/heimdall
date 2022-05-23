package cache

type Evictor interface {
	Start()
	Stop()
}
