package types

import "strings"

type Reference struct {
	Source   string
	Selector string
}

func (r Reference) Parent() Reference {
	if idx := strings.LastIndex(r.Selector, "/"); idx < 0 {
		r.Selector = ""
	} else {
		r.Selector = r.Selector[:idx]
	}

	return r
}

