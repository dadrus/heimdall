package provider

import "encoding/json"

type ChangeType uint32

// These are the generalized file operations that can trigger a notification.
const (
	Create ChangeType = 1 << iota
	Write
	Remove
)

type RuleSetChangedEvent struct {
	Src        string
	Definition json.RawMessage
	ChangeType ChangeType
}
