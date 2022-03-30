package oauth2

func getClaim[T any](claims map[string]interface{}, name string, defVal T) T {
	if c, ok := claims[name]; ok {
		if v, ok := c.(T); !ok {
			return defVal
		} else {
			return v
		}
	}

	return defVal
}
