// Copyright 2022 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package topdown

import (
	"context"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/storage"
	inmem "github.com/open-policy-agent/opa/storage/inmem/test"
)

// For the purposes of addressing the original Github issue (#4409), a
// fairly shallow object with many keys ought to do the trick.
func gen3LayerObject(l1Keys, l2Keys, l3Keys int) ast.Value {
	obj := ast.NewObject()
	for i := 0; i < l1Keys; i++ {
		l2Obj := ast.NewObject()
		for j := 0; j < l2Keys; j++ {
			l3Obj := ast.NewObject()
			for k := 0; k < l3Keys; k++ {
				l3Obj.Insert(ast.StringTerm(fmt.Sprintf("%d", k)), ast.BooleanTerm(true))
			}
			l2Obj.Insert(ast.StringTerm(fmt.Sprintf("%d", j)), ast.NewTerm(l3Obj))
		}
		obj.Insert(ast.StringTerm(fmt.Sprintf("%d", i)), ast.NewTerm(l2Obj))
	}
	return obj
}

// Generates a list of paths for JSON operations. N keys per level, M levels. P patches.
// TODO: Generate non-conflicting paths.
func genRandom3LayerObjectJSONPatchListData(l1Keys, l2Keys, l3Keys, p int) ast.Value {
	patchList := make([]*ast.Term, p)
	numKeys := []int{l1Keys, l2Keys, l3Keys}
	for i := 0; i < p; i++ {
		patchObj := ast.NewObject(
			[2]*ast.Term{ast.StringTerm("op"), ast.StringTerm("replace")},
			[2]*ast.Term{ast.StringTerm("value"), ast.IntNumberTerm(2)},
		)
		// Random path depth.
		depth := rand.Intn(3) + 1 // (max - min) + min method of getting a random range.

		// Random values for each path segment.
		segments := []string{}
		for j := 0; j < depth; j++ {
			pathSegment := strconv.FormatInt(int64(rand.Intn(numKeys[j])), 10)
			segments = append(segments, "/", pathSegment)
		}
		path := strings.Join(segments, "")
		patchObj.Insert(ast.StringTerm("path"), ast.StringTerm(path))
		patchList[i] = ast.NewTerm(patchObj)
	}
	return ast.NewArray(patchList...)
}

func BenchmarkJSONPatchReplace(b *testing.B) {
	ctx := context.Background()

	sizes := []int{10, 100, 1000}

	// Pre-generate the test datasets/patches.
	testdata := map[string][2]ast.Value{}
	for _, n := range sizes {
		for _, m := range sizes {
			testObj := gen3LayerObject(n, m, 10)
			for _, p := range sizes {
				testdata[fmt.Sprintf("%dx%dx10-%dp", n, m, p)] = [2]ast.Value{testObj, genRandom3LayerObjectJSONPatchListData(n, m, 10, p)}
			}
		}
	}

	for _, n := range sizes {
		for _, m := range sizes {
			for _, p := range sizes {
				testName := fmt.Sprintf("%dx%dx10-%dp", n, m, p)
				b.Run(testName, func(b *testing.B) {
					store := inmem.NewFromObject(map[string]interface{}{
						"obj":     testdata[testName][0],
						"patches": testdata[testName][1],
					})

					module := `package test

					result := json.patch(data.obj, data.patches)`

					query := ast.MustParseBody("data.test.result")
					compiler := ast.MustCompileModules(map[string]string{
						"test.rego": module,
					})

					b.ResetTimer()

					for i := 0; i < b.N; i++ {

						err := storage.Txn(ctx, store, storage.TransactionParams{}, func(txn storage.Transaction) error {

							q := NewQuery(query).
								WithCompiler(compiler).
								WithStore(store).
								WithTransaction(txn)

							_, err := q.Run(ctx)
							if err != nil {
								return err
							}

							return nil
						})

						if err != nil {
							b.Fatal(err)
						}
					}
				})
			}
		}
	}
}
