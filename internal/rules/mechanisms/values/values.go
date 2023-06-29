package values

import "golang.org/x/exp/maps"

type Values map[string]string

func (v Values) Merge(other Values) Values {
	if len(other) == 0 {
		return v
	}

	var res Values

	if v == nil {
		res = make(Values)
	} else {
		res = maps.Clone(v)
	}

	for key, value := range other {
		res[key] = value
	}

	return res
}
