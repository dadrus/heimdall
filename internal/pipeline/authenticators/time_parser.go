package authenticators

import (
	"strconv"
	"time"
)

type ParseTime func(value string) (time.Time, error)

func TimeParser(format string) ParseTime {
	switch format {
	case "ANSIC":
		return func(value string) (time.Time, error) { return time.Parse(time.ANSIC, value) }
	case "UnixDate":
		return func(value string) (time.Time, error) { return time.Parse(time.UnixDate, value) }
	case "RFC822":
		return func(value string) (time.Time, error) { return time.Parse(time.RFC822, value) }
	case "RFC822Z":
		return func(value string) (time.Time, error) { return time.Parse(time.RFC822Z, value) }
	case "RFC850":
		return func(value string) (time.Time, error) { return time.Parse(time.RFC850, value) }
	case "RFC1123":
		return func(value string) (time.Time, error) { return time.Parse(time.RFC1123, value) }
	case "RFC1123Z":
		return func(value string) (time.Time, error) { return time.Parse(time.RFC1123Z, value) }
	case "RFC3339":
		return func(value string) (time.Time, error) { return time.Parse(time.RFC3339, value) }
	case "Unix":
		return func(value string) (time.Time, error) {
			intVal, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return time.Time{}, err
			}

			return time.UnixMilli(intVal), nil
		}
	default:
		return func(value string) (time.Time, error) { return time.Parse(format, value) }
	}
}
