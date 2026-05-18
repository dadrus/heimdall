package source

import "github.com/dadrus/heimdall/internal/secrets/types"

type Event struct {
	Source    string
	Selectors []types.Selector
}

type Observer interface {
	Notify(evt Event)
}
