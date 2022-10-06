package exporters

import "os"

func envOr(key, defaultValue string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}

	return defaultValue
}
