package x

func OrDefault[T comparable](val, defaultVal T) T {
	var t T

	if val == t {
		return defaultVal
	}

	return val
}

func IfThenElse[T any](c bool, thenVal, elseVal T) T {
	if c {
		return thenVal
	}
	
	return elseVal
}
