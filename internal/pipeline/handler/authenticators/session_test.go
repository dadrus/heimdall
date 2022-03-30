package authenticators

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
)

func TestSessionValidation(t *testing.T) {
	for _, tc := range []struct {
		uc        string
		configure func(t *testing.T, s *Session)
		assert    func(t *testing.T, err error)
	}{
		{
			uc: "subject_from is set",
			configure: func(t *testing.T, s *Session) {
				s.SubjectFrom = "foobar"
			},
			assert: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			uc:        "subject_from is not set",
			configure: func(t *testing.T, s *Session) {},
			assert: func(t *testing.T, err error) {
				assert.Error(t, err)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			s := Session{}
			tc.configure(t, &s)

			// WHEN
			err := s.Validate()

			// THEN
			tc.assert(t, err)
		})
	}
}

func TestGetSubjectFromSession(t *testing.T) {
	type nested struct {
		Val bool `json:"val"`
	}

	type complex struct {
		Array  []int  `json:"array"`
		Nested nested `json:"nested"`
	}
	type idt struct {
		Subject             string   `json:"subject"`
		SomeStringAttribute string   `json:"some_string_attribute"`
		SomeInt64Attribute  int64    `json:"some_int_64_attribute"`
		StringSlice         []string `json:"string_slice"`
		Complex             complex  `json:"complex"`
	}

	id := idt{
		Subject:             "foo",
		SomeStringAttribute: "attr",
		SomeInt64Attribute:  -6,
		StringSlice:         []string{"val1", "val2"},
		Complex: complex{
			Array:  []int{1, 2, 3},
			Nested: nested{Val: true},
		},
	}

	raw, err := json.Marshal(id)
	require.NoError(t, err)

	for _, tc := range []struct {
		uc        string
		configure func(t *testing.T, s *Session)
		assert    func(t *testing.T, err error, sub *heimdall.Subject)
	}{
		{
			uc: "subject is extracted and attributes are the whole object",
			configure: func(t *testing.T, s *Session) {
				s.SubjectFrom = "subject"
			},
			assert: func(t *testing.T, err error, sub *heimdall.Subject) {
				assert.NoError(t, err)
				assert.Equal(t, "foo", sub.Id)

				var attrs map[string]interface{}
				e := json.Unmarshal(raw, &attrs)
				assert.NoError(t, e)
				assert.Equal(t, attrs, sub.Attributes)
			},
		},
		{
			uc: "subject is extracted and attributes are the nested object",
			configure: func(t *testing.T, s *Session) {
				s.SubjectFrom = "string_slice.1"
				s.AttributesFrom = "complex.nested"
			},
			assert: func(t *testing.T, err error, sub *heimdall.Subject) {
				assert.NoError(t, err)
				assert.Equal(t, "val2", sub.Id)

				rawNested, err := json.Marshal(id.Complex.Nested)
				require.NoError(t, err)

				var attrs map[string]interface{}
				e := json.Unmarshal(rawNested, &attrs)
				assert.NoError(t, e)
				assert.Equal(t, attrs, sub.Attributes)
			},
		},
		{
			uc: "subject is extracted but not attributes",
			configure: func(t *testing.T, s *Session) {
				s.SubjectFrom = "subject"
				s.AttributesFrom = "foobar"
			},
			assert: func(t *testing.T, err error, sub *heimdall.Subject) {
				assert.NoError(t, err)
				assert.Equal(t, "foo", sub.Id)
				assert.Empty(t, sub.Attributes)
			},
		},
		{
			uc: "subject could not be extracted",
			configure: func(t *testing.T, s *Session) {
				s.SubjectFrom = "foo"
			},
			assert: func(t *testing.T, err error, sub *heimdall.Subject) {
				assert.Error(t, err)
				assert.Nil(t, sub)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			s := Session{}
			tc.configure(t, &s)

			// WHEN
			sub, err := s.GetSubject(raw)

			// THEN
			tc.assert(t, err, sub)
		})
	}
}
