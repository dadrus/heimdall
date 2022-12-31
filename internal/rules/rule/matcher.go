package rule

import "github.com/goccy/go-json"

type Matcher struct {
	URL      string `json:"url" yaml:"url"`
	Strategy string `json:"strategy" yaml:"strategy"`
}

func (m *Matcher) UnmarshalJSON(data []byte) error {
	if data[0] == '"' {
		// data contains just the url matching value
		m.URL = string(data[1 : len(data)-1])
		m.Strategy = "glob"

		return nil
	}

	var rawData map[string]any

	if err := json.Unmarshal(data, &rawData); err != nil {
		return err
	}

	return DecodeConfig(rawData, m)
}
