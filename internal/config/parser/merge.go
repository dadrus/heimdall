package parser

import (
	"github.com/mitchellh/mapstructure"
	"reflect"
)

func merge(dest, src any) any {
	if dest == nil {
		return cleanSuffix(src)
	}

	vDst := reflect.ValueOf(dest)
	vSrc := reflect.ValueOf(src)

	if vSrc.Type() != vDst.Type() {
		// try decode
		if err := mapstructure.Decode(vSrc, &vDst); err != nil {
			panic(err.Error())
		}
		//panic(fmt.Sprintf("Cannot merge %s and %s. Types are different: %s - %s", dest, src, vDst.Type(), vSrc.Type()))
	}

	// nolint: exhaustive
	switch vDst.Kind() {
	case reflect.Map:
		// nolint: forcetypeassert
		return mergeMaps(dest.(map[string]any), src.(map[string]any))
	case reflect.Slice:
		// nolint: forcetypeassert
		return mergeSlices(dest.([]any), src.([]any))
	default:
		// any other (primitive) type
		// overriding
		return src
	}
}

func mergeSlices(dest, src []any) []any {
	if len(dest) < len(src) {
		oldDest := dest
		dest = make([]any, len(src))

		copy(dest, oldDest)
	}

	for i, v := range src {
		avail := dest[i]
		if avail == nil {
			dest[i] = v
		} else if v != nil {
			dest[i] = merge(avail, v)
		}
	}

	return dest
}

func mergeMaps(dest, src map[string]any) map[string]any {
	for k, v := range src {
		old := dest[k]
		if old == nil {
			dest[k] = v
		} else {
			dest[k] = merge(old, v)
		}
	}

	return dest
}
