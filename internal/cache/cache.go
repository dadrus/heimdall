package cache

import (
	"time"
)

type Cache interface {
	Start()
	Stop()
	Get(key string) any
	Set(key string, value any, ttl time.Duration)
	Delete(key string)
}
