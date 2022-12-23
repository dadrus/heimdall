package testsupport

import (
	"bytes"
	"fmt"
	"testing"
)

type TestingLog struct {
	testing.TB
	buf bytes.Buffer
}

func (t *TestingLog) Log(args ...interface{}) {
	if _, err := t.buf.WriteString(fmt.Sprint(args...)); err != nil {
		t.Error(err)
	}
}

func (t *TestingLog) Logf(format string, args ...interface{}) {
	if _, err := t.buf.WriteString(fmt.Sprintf(format, args...)); err != nil {
		t.Error(err)
	}
}

func (t *TestingLog) CollectedLog() string {
	return t.buf.String()
}
