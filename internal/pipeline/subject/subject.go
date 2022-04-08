package subject

type Subject struct {
	ID         string         `json:"id"`
	Attributes map[string]any `json:"attributes"`
}
