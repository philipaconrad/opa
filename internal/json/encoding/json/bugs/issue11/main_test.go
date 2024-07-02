package main

import (
	"fmt"
	"log"
	"testing"

	"github.com/open-policy-agent/opa/internal/json/encoding/json"
)

func TestIssue11(t *testing.T) {
	m := map[string]map[string]interface{}{
		"outerkey": {
			"innerkey": "innervalue",
		},
	}

	b, err := json.Marshal(m)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(b))
}
