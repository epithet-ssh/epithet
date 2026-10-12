package object_test

import (
	"encoding/json"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/writ/object"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestStringValuesAtProviderBoundary(t *testing.T) {
	for _, tc := range []struct {
		input   string
		want    object.Values
		invalid bool
	}{
		{`null`, nil, false}, {`[]`, object.Values{}, false}, {`""`, object.Values{""}, false},
		{`"123"`, object.Values{"123"}, false}, {`["ops","oncall"]`, object.Values{"ops", "oncall"}, false},
		{`123`, nil, true}, {`true`, nil, true}, {`{}`, nil, true}, {`["ops",null]`, nil, true},
		{`["ops",false]`, nil, true}, {`[[]]`, nil, true},
	} {
		t.Run(tc.input, func(t *testing.T) {
			for _, decode := range []func([]byte, any) error{json.Unmarshal, yaml.Unmarshal} {
				var got object.Values
				err := decode([]byte(tc.input), &got)
				if tc.invalid {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
					require.Equal(t, tc.want, got)
				}
			}
		})
	}
}

func TestDefinedFieldsCannotBeShadowed(t *testing.T) {
	for _, key := range []string{"name", "id"} {
		u := object.User{ID: "subject", Attributes: object.Attributes{key: {"forged"}}}
		require.Error(t, u.Validate("subject"))
		u.Attributes = nil
		u.Groups = []object.Object{{Attributes: object.Attributes{key: {"forged"}}}}
		require.Error(t, u.Validate("subject"))
	}
	require.Error(t, (object.User{}).Validate(""))
	require.Error(t, (object.User{ID: "other"}).Validate("subject"))
	require.NoError(t, (object.User{ID: "subject", Groups: []object.Object{{Names: []string{"ops"}}}}).Validate("subject"))
}
