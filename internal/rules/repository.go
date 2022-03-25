package rules

import (
	"net/url"

	"github.com/dadrus/heimdall/internal/config"
)

type Repository interface {
	FindRule(method string, requestUrl *url.URL) (*Rule, error)
}

func NewRepository(conf config.Configuration) (Repository, error) {
	return &repository{}, nil
}

type repository struct {
}

func (r *repository) FindRule(method string, requestUrl *url.URL) (*Rule, error) {
	return nil, nil
}
