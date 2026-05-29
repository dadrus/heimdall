package pem

import (
	"os"

	"github.com/dadrus/heimdall/internal/secrets/provider"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

func readFile(path string) ([]byte, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return nil, errorchain.NewWithMessagef(provider.ErrConfiguration,
			"failed to get information about %s", path).CausedBy(err)
	}

	if fileInfo.IsDir() {
		return nil, errorchain.NewWithMessagef(provider.ErrConfiguration, "'%s' is not a file", path)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, errorchain.NewWithMessagef(provider.ErrConfiguration,
			"failed to read %s", path).CausedBy(err)
	}

	return contents, nil
}
