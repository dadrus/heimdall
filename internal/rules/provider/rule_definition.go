package provider

import "encoding/json"

type ChangeType uint32

// These are the generalized file operations that can trigger a notification.
const (
	Create ChangeType = 1 << iota
	Remove
)

func (t ChangeType) String() string {
	if t == Create {
		return "Create"
	}

	return "Remove"
}

type RuleSetChangedEvent struct {
	Src        string
	Definition json.RawMessage
	ChangeType ChangeType
}
