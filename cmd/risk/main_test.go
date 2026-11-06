package main

import (
	"bytes"
	"strings"
	"testing"
)

// The currency command refuses malformed arguments before it connects.
func TestCurrencyArgs(t *testing.T) {
	for _, c := range []struct {
		args []string
		want string
	}{
		{nil, "usage"},
		{[]string{"get"}, "usage"},
		{[]string{"set"}, "usage"},
		{[]string{"set", "-operator", "x"}, "usage"},
		{[]string{"set", "USD"}, "-operator is required"},
		{[]string{"set", "USD", "-operator", "x", "extra"}, "usage"},
		{[]string{"show", "extra"}, "usage"},
	} {
		var out bytes.Buffer
		if err := currency(c.args, &out); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v: %v, want %q", c.args, err, c.want)
		}
	}
}
