package endpoint

type Renderer interface {
	Render(value string) (string, error)
}

type RenderFunc func(value string) (string, error)

func (f RenderFunc) Render(value string) (string, error) { return f(value) }
