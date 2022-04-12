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

func IfThenElseExec[T any](c bool, thenFunc func() T, elseFunc func() T) T {
	if c {
		return thenFunc()
	}

	return elseFunc()
}
