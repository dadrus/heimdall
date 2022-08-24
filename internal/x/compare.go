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

func IfThenElseExecErr[T any](c bool, thenFunc func() (T, error), elseFunc func() (T, error)) (T, error) {
	if c {
		return thenFunc()
	}

	return elseFunc()
}
