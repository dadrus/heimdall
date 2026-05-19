package types

type Store interface {
	RegisterSecret(ref Reference) error
	GetSecret(ref Reference) (string, error)
	CleanUp()
}
