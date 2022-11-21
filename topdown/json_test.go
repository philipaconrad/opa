// Copyright 2019 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package topdown

import (
	"reflect"
	"testing"

	"github.com/open-policy-agent/opa/ast"
)

func TestFiltersToObject(t *testing.T) {
	cases := []struct {
		note     string
		filters  []string
		expected string
	}{
		{
			note:     "empty path",
			filters:  []string{`""`},
			expected: `{}`,
		},
		{
			note:     "base",
			filters:  []string{`"a/b/c"`},
			expected: `{"a": {"b": {"c": null}}}`,
		},
		{
			note:     "root prefixed",
			filters:  []string{`"a/b/c"`},
			expected: `{"a": {"b": {"c": null}}}`,
		},
		{
			note:     "trailing slash",
			filters:  []string{`"a/b/c"`},
			expected: `{"a": {"b": {"c": null}}}`,
		},
		{
			note:     "different roots",
			filters:  []string{`"a/b/c"`, `"d/e/f"`},
			expected: `{"a": {"b": {"c": null}}, "d": {"e": {"f": null}}}`,
		},
		{
			note:     "shared root",
			filters:  []string{`"a/b/c"`, `"a/b/d"`},
			expected: `{"a": {"b": {"c": null, "d": null}}}`,
		},
		{
			note:     "multiple shares at different points",
			filters:  []string{`"a/b/c"`, `"a/b/d"`, `"a/e/f"`},
			expected: `{"a": {"b": {"c": null, "d": null}, "e": {"f": null}}}`,
		},
		{
			note:     "conflict with one ordering",
			filters:  []string{`"a"`, `"a/b"`},
			expected: `{"a": null}`,
		},
		{
			note:     "conflict with reverse ordering",
			filters:  []string{`"a/b"`, `"a"`},
			expected: `{"a": null}`,
		},
		{
			note:     "arrays",
			filters:  []string{`"a/1/c"`, `"a/1/b"`},
			expected: `{"a": {"1": {"c": null, "b": null}}}`,
		},
		{
			note:     "non string keys",
			filters:  []string{`[[1], {2}]`, `"a/1/b"`},
			expected: `{"a": {"1": {"b": null}}, [1]: {{2}: null}}`,
		},
		{
			note:     "escaped tilde",
			filters:  []string{`"a/~0b~0/c~0"`},
			expected: `{"a": {"~b~": {"c~": null}}}`,
		},
		{
			note:     "escaped slash",
			filters:  []string{`"a/~1b~1c/d~1"`},
			expected: `{"a": {"/b/c": {"d/": null}}}`,
		},
		{
			note:     "mixed escapes",
			filters:  []string{`"a/~0b~1c/d~1~0"`},
			expected: `{"a": {"~b/c": {"d/~": null}}}`,
		},
		{
			note:     "empty strings mixed with normal paths",
			filters:  []string{`"a/b/c"`, `""`, `"a/b/d"`, `"a/e/f"`, `""`},
			expected: `{"a": {"b": {"c": null, "d": null}, "e": {"f": null}}}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.note, func(t *testing.T) {
			var paths []ast.Ref
			for _, path := range tc.filters {
				parsedPath, err := parsePath(ast.MustParseTerm(path))
				if err != nil {
					t.Errorf("unexpected error parsing path %s: %s", path, err)
				}
				paths = append(paths, parsedPath)
			}
			actual := pathsToObject(paths)
			expected := ast.MustParseTerm(tc.expected)
			if actual.Compare(expected.Value) != 0 {
				t.Errorf("Unexpected object from filters:\n\nExpected:\n\t%s\n\nActual:\n\t%s\n\n", expected.Value.String(), actual.String())
			}
		})
	}
}

// Tests to make sure that the DAG construction handles edge cases properly.
func TestBuildPatchSeqDAG(t *testing.T) {
	// These tests focus on the tricky success cases, not on error handling.
	cases := []struct {
		note           string
		object         string
		patches        []string
		expUnsatKeys   map[string][]int
		expActiveHeads map[int]struct{}
		expPatchChain  map[int][]int
	}{
		// Ops on top-level keys only.
		{
			note:           "simple add",
			patches:        []string{`{"op": "add", "path": "/b", "value": 3}`},
			expUnsatKeys:   map[string][]int{},
			expActiveHeads: map[int]struct{}{0: {}},
			expPatchChain:  map[int][]int{0: {0}},
		},
		{
			note:           "simple remove",
			patches:        []string{`{"op": "remove", "path": "/a"}`},
			expUnsatKeys:   map[string][]int{"/a": {0}},
			expActiveHeads: map[int]struct{}{0: {}},
			expPatchChain:  map[int][]int{0: {0}},
		},
		{
			note:           "simple replace",
			patches:        []string{`{"op": "replace", "path": "/a", "value": 3}`},
			expUnsatKeys:   map[string][]int{"/a": {0}},
			expActiveHeads: map[int]struct{}{0: {}},
			expPatchChain:  map[int][]int{0: {0}},
		},
		{
			note:           "simple move",
			patches:        []string{`{"op": "move", "path": "/b", "from": "/a"}`},
			expUnsatKeys:   map[string][]int{"/a": {0}},
			expActiveHeads: map[int]struct{}{0: {}},
			expPatchChain:  map[int][]int{0: {0}},
		},
		{
			note:           "simple copy",
			patches:        []string{`{"op": "copy", "path": "/b", "from": "/a"}`},
			expUnsatKeys:   map[string][]int{"/a": {0}},
			expActiveHeads: map[int]struct{}{0: {}},
			expPatchChain:  map[int][]int{0: {0}},
		},
		{
			note:           "simple test",
			patches:        []string{`{"op": "test", "path": "/a", "value": 2}`},
			expUnsatKeys:   map[string][]int{"/a": {0}},
			expActiveHeads: map[int]struct{}{0: {}},
			expPatchChain:  map[int][]int{0: {0}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.note, func(t *testing.T) {
			patches := ast.NewArray()
			for i := range tc.patches {
				patches = patches.Append(ast.MustParseTerm(tc.patches[i]))
			}

			psd, err := BuildPatchSeqDAG(patches)
			if err != nil {
				t.Errorf("unexpected error: %s", err)
			}

			if !reflect.DeepEqual(tc.expUnsatKeys, psd.unsatKeys) {
				t.Errorf("Wrong unsat keys generated from patch list:\n\nExpected:\n\t%v\n\nActual:\n\t%v\n\n", tc.expUnsatKeys, psd.unsatKeys)
			}
			if !reflect.DeepEqual(tc.expActiveHeads, psd.activeHeads) {
				t.Errorf("Wrong active heads generated from patch list:\n\nExpected:\n\t%v\n\nActual:\n\t%v\n\n", tc.expActiveHeads, psd.activeHeads)
			}
			if !reflect.DeepEqual(tc.expPatchChain, psd.patchChainDAG) {
				t.Errorf("Wrong patch chain generated from patch list:\n\nExpected:\n\t%v\n\nActual:\n\t%v\n\n", tc.expPatchChain, psd.patchChainDAG)
			}
		})
	}
}
