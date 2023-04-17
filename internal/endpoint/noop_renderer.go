package endpoint

type noopRenderer struct{}

func (noopRenderer) Render(template string, _ map[string]string) (string, error) {
	return template, nil
}
