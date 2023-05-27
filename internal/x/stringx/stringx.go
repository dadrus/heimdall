package stringx

import "unsafe"

func ToString(b []byte) string {
	return unsafe.String(unsafe.SliceData(b), len(b))
}

func ToBytes(str string) []byte {
	return unsafe.Slice(unsafe.StringData(str), len(str))
}
