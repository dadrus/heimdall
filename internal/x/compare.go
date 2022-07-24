package x

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
