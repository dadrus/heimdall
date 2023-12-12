package config

type CacheProviders struct {
	Type   string         `koanf:"type"`
	Config map[string]any `koanf:"config"`
	// Redis        map[string]any `koanf:"redis,omitempty"`
	// RedisCluster map[string]any `koanf:"redis-cluster,omitempty"`
	// Noop         map[string]any `koanf:"noop,omitempty"`
	// Memory       map[string]any `koanf:"memory,omitempty"`
}
