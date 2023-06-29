package endpoint

type noopRenderer struct{}

func (noopRenderer) Render(template string) (string, error) {
	return template, nil
}
