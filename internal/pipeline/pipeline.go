package pipeline

type Pipeline interface {
	Execute(ctx Context, subject Subject) error
}
