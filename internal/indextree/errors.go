package indextree

import "errors"

var (
	ErrInvalidPath    = errors.New("invalid path")
	ErrNotFound       = errors.New("not found")
	ErrFailedToDelete = errors.New("failed to delete")
)
