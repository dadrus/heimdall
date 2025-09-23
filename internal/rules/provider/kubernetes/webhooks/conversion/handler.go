package conversion

import (
	"net/http"

	"github.com/dadrus/heimdall/internal/rules/provider/kubernetes/api/webhook"
)

func NewHandler() http.Handler {
	return webhook.New(
		&rulesetConverter{},
		&review{},
	)
}
