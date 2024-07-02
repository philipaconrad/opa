package main

import (
	"testing"

	"github.com/open-policy-agent/opa/internal/json/encoding/json"
)

type Foo struct {
	Source struct {
		Table string
	}
}

func TestUnmarshal(t *testing.T) {
	input := []byte(`{"source": {"table": "1234567"}}`)
	r := &Foo{}
	json.Unmarshal(input, r)
}
