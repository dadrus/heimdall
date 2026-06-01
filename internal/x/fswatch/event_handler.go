package fswatch

// Op describes the type of change observed for a path.
type Op uint8

const (
	// OpAdded means that a path was added below a watched directory.
	//
	// OpAdded is emitted only for entries below watched directories. It is not
	// emitted during initial watcher setup.
	OpAdded Op = iota + 1

	// OpChanged means that the content or target of a watched path changed.
	//
	// For file roots, this means the watched file changed.
	// For directory roots, this can either mean a child changed or that the
	// watched directory itself was rebound, e.g. by a symlink target switch.
	OpChanged

	// OpDeleted means that a watched path or an entry below a watched directory
	// was removed or is no longer accessible.
	OpDeleted
)

func (o Op) String() string {
	switch o {
	case OpAdded:
		return "added"
	case OpChanged:
		return "changed"
	case OpDeleted:
		return "deleted"
	default:
		return "unknown"
	}
}

// Event is a normalized filesystem event.
//
// For file roots, Path is the watched file path.
// For directory roots, Path is either an affected child path or the watched
// directory path itself when the directory target changed.
type Event struct {
	Path string
	Op   Op
}

// EventHandler receives normalized filesystem events.
type EventHandler interface {
	HandleEvent(evt Event) error
}

// EventHandlerFunc adapts a function to EventHandler.
type EventHandlerFunc func(evt Event) error

// HandleEvent implements EventHandler.
func (f EventHandlerFunc) HandleEvent(evt Event) error {
	return f(evt)
}
