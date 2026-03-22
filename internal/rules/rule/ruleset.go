package rule

type RuleSet struct {
	ID       string
	Name     string
	Provider string
}

func (r RuleSet) Equals(other RuleSet) bool {
	// the Name is ignored by intention. It is not part of the unique identifier
	return r.ID == other.ID && r.Provider == other.Provider
}
