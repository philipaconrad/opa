// Copyright 2019 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package topdown

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/topdown/builtins"
)

func builtinJSONRemove(_ BuiltinContext, operands []*ast.Term, iter func(*ast.Term) error) error {

	// Expect an object and a string or array/set of strings
	_, err := builtins.ObjectOperand(operands[0].Value, 1)
	if err != nil {
		return err
	}

	// Build a list of json pointers to remove
	paths, err := getJSONPaths(operands[1].Value)
	if err != nil {
		return err
	}

	newObj, err := jsonRemove(operands[0], ast.NewTerm(pathsToObject(paths)))
	if err != nil {
		return err
	}

	if newObj == nil {
		return nil
	}

	return iter(newObj)
}

// jsonRemove returns a new term that is the result of walking
// through a and omitting removing any values that are in b but
// have ast.Null values (ie leaf nodes for b).
func jsonRemove(a *ast.Term, b *ast.Term) (*ast.Term, error) {
	if b == nil {
		// The paths diverged, return a
		return a, nil
	}

	var bObj ast.Object
	switch bValue := b.Value.(type) {
	case ast.Object:
		bObj = bValue
	case ast.Null:
		// Means we hit a leaf node on "b", dont add the value for a
		return nil, nil
	default:
		// The paths diverged, return a
		return a, nil
	}

	switch aValue := a.Value.(type) {
	case ast.String, ast.Number, ast.Boolean, ast.Null:
		return a, nil
	case ast.Object:
		newObj := ast.NewObject()
		err := aValue.Iter(func(k *ast.Term, v *ast.Term) error {
			// recurse and add the diff of sub objects as needed
			diffValue, err := jsonRemove(v, bObj.Get(k))
			if err != nil || diffValue == nil {
				return err
			}
			newObj.Insert(k, diffValue)
			return nil
		})
		if err != nil {
			return nil, err
		}
		return ast.NewTerm(newObj), nil
	case ast.Set:
		newSet := ast.NewSet()
		err := aValue.Iter(func(v *ast.Term) error {
			// recurse and add the diff of sub objects as needed
			diffValue, err := jsonRemove(v, bObj.Get(v))
			if err != nil || diffValue == nil {
				return err
			}
			newSet.Add(diffValue)
			return nil
		})
		if err != nil {
			return nil, err
		}
		return ast.NewTerm(newSet), nil
	case *ast.Array:
		// When indexes are removed we shift left to close empty spots in the array
		// as per the JSON patch spec.
		newArray := ast.NewArray()
		for i := 0; i < aValue.Len(); i++ {
			v := aValue.Elem(i)
			// recurse and add the diff of sub objects as needed
			// Note: Keys in b will be strings for the index, eg path /a/1/b => {"a": {"1": {"b": null}}}
			diffValue, err := jsonRemove(v, bObj.Get(ast.StringTerm(strconv.Itoa(i))))
			if err != nil {
				return nil, err
			}
			if diffValue != nil {
				newArray = newArray.Append(diffValue)
			}
		}
		return ast.NewTerm(newArray), nil
	default:
		return nil, fmt.Errorf("invalid value type %T", a)
	}
}

func builtinJSONFilter(_ BuiltinContext, operands []*ast.Term, iter func(*ast.Term) error) error {

	// Ensure we have the right parameters, expect an object and a string or array/set of strings
	obj, err := builtins.ObjectOperand(operands[0].Value, 1)
	if err != nil {
		return err
	}

	// Build a list of filter strings
	filters, err := getJSONPaths(operands[1].Value)
	if err != nil {
		return err
	}

	// Actually do the filtering
	filterObj := pathsToObject(filters)
	r, err := obj.Filter(filterObj)
	if err != nil {
		return err
	}

	return iter(ast.NewTerm(r))
}

func getJSONPaths(operand ast.Value) ([]ast.Ref, error) {
	var paths []ast.Ref

	switch v := operand.(type) {
	case *ast.Array:
		for i := 0; i < v.Len(); i++ {
			filter, err := parsePath(v.Elem(i))
			if err != nil {
				return nil, err
			}
			paths = append(paths, filter)
		}
	case ast.Set:
		err := v.Iter(func(f *ast.Term) error {
			filter, err := parsePath(f)
			if err != nil {
				return err
			}
			paths = append(paths, filter)
			return nil
		})
		if err != nil {
			return nil, err
		}
	default:
		return nil, builtins.NewOperandTypeErr(2, v, "set", "array")
	}

	return paths, nil
}

func parsePath(path *ast.Term) (ast.Ref, error) {
	// paths can either be a `/` separated json path or
	// an array or set of values
	var pathSegments ast.Ref
	switch p := path.Value.(type) {
	case ast.String:
		if p == "" {
			return ast.Ref{}, nil
		}
		parts := strings.Split(strings.TrimLeft(string(p), "/"), "/")
		for _, part := range parts {
			part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
			pathSegments = append(pathSegments, ast.StringTerm(part))
		}
	case *ast.Array:
		p.Foreach(func(term *ast.Term) {
			pathSegments = append(pathSegments, term)
		})
	default:
		return nil, builtins.NewOperandErr(2, "must be one of {set, array} containing string paths or array of path segments but got %v", ast.TypeName(p))
	}

	return pathSegments, nil
}

func pathsToObject(paths []ast.Ref) ast.Object {

	root := ast.NewObject()

	for _, path := range paths {
		node := root
		var done bool

		// If the path is an empty JSON path, skip all further processing.
		if len(path) == 0 {
			done = true
		}

		// Otherwise, we should have 1+ path segments to work with.
		for i := 0; i < len(path)-1 && !done; i++ {

			k := path[i]
			child := node.Get(k)

			if child == nil {
				obj := ast.NewObject()
				node.Insert(k, ast.NewTerm(obj))
				node = obj
				continue
			}

			switch v := child.Value.(type) {
			case ast.Null:
				done = true
			case ast.Object:
				node = v
			default:
				panic("unreachable")
			}
		}

		if !done {
			node.Insert(path[len(path)-1], ast.NullTerm())
		}
	}

	return root
}

// toIndex tries to convert path elements (that may be strings) into indices into
// an array.
func toIndex(arr *ast.Array, term *ast.Term) (int, error) {
	i := 0
	var ok bool
	switch v := term.Value.(type) {
	case ast.Number:
		if i, ok = v.Int(); !ok {
			return 0, fmt.Errorf("Invalid number type for indexing")
		}
	case ast.String:
		if v == "-" {
			return arr.Len(), nil
		}
		num := ast.Number(v)
		if i, ok = num.Int(); !ok {
			return 0, fmt.Errorf("Invalid string for indexing")
		}
		if v != "0" && strings.HasPrefix(string(v), "0") {
			return 0, fmt.Errorf("Leading zeros are not allowed in JSON paths")
		}
	default:
		return 0, fmt.Errorf("Invalid type for indexing")
	}

	return i, nil
}

// patchWorker is a worker that modifies a direct child of a term located
// at the given key.  It returns the new term, and optionally a result that
// is passed back to the caller.
type patchWorker = func(parent, key *ast.Term) (updated, result *ast.Term)

func jsonPatchTraverse(
	target *ast.Term,
	path ast.Ref,
	worker patchWorker,
) (*ast.Term, *ast.Term) {
	if len(path) < 1 {
		return nil, nil
	}

	key := path[0]
	if len(path) == 1 {
		return worker(target, key)
	}

	success := false
	var updated, result *ast.Term
	switch parent := target.Value.(type) {
	case ast.Object:
		obj := ast.NewObject()
		parent.Foreach(func(k, v *ast.Term) {
			if k.Equal(key) {
				if v, result = jsonPatchTraverse(v, path[1:], worker); v != nil {
					obj.Insert(k, v)
					success = true
				}
			} else {
				obj.Insert(k, v)
			}
		})
		updated = ast.NewTerm(obj)

	case *ast.Array:
		idx, err := toIndex(parent, key)
		if err != nil {
			return nil, nil
		}
		arr := ast.NewArray()
		for i := 0; i < parent.Len(); i++ {
			v := parent.Elem(i)
			if idx == i {
				if v, result = jsonPatchTraverse(v, path[1:], worker); v != nil {
					arr = arr.Append(v)
					success = true
				}
			} else {
				arr = arr.Append(v)
			}
		}
		updated = ast.NewTerm(arr)

	case ast.Set:
		set := ast.NewSet()
		parent.Foreach(func(k *ast.Term) {
			if k.Equal(key) {
				if k, result = jsonPatchTraverse(k, path[1:], worker); k != nil {
					set.Add(k)
					success = true
				}
			} else {
				set.Add(k)
			}
		})
		updated = ast.NewTerm(set)
	}

	if success {
		return updated, result
	}

	return nil, nil
}

// jsonPatchGet goes one step further than jsonPatchTraverse and returns the
// term at the location specified by the path.  It is used in functions
// where we want to read a value but not manipulate its parent: for example
// jsonPatchTest and jsonPatchCopy.
//
// Because it uses jsonPatchTraverse, it makes shallow copies of the objects
// along the path.  We could possibly add a signaling mechanism that we didn't
// make any changes to avoid this.
func jsonPatchGet(target *ast.Term, path ast.Ref) *ast.Term {
	// Special case: get entire document.
	if len(path) == 0 {
		return target
	}

	_, result := jsonPatchTraverse(target, path, func(parent, key *ast.Term) (*ast.Term, *ast.Term) {
		switch v := parent.Value.(type) {
		case ast.Object:
			return parent, v.Get(key)
		case *ast.Array:
			i, err := toIndex(v, key)
			if err == nil {
				return parent, v.Elem(i)
			}
		case ast.Set:
			if v.Contains(key) {
				return parent, key
			}
		}
		return nil, nil
	})
	return result
}

func jsonPatchAdd(target *ast.Term, path ast.Ref, value *ast.Term) *ast.Term {
	// Special case: replacing root document.
	if len(path) == 0 {
		return value
	}

	target, _ = jsonPatchTraverse(target, path, func(parent *ast.Term, key *ast.Term) (*ast.Term, *ast.Term) {
		switch original := parent.Value.(type) {
		case ast.Object:
			obj := ast.NewObject()
			original.Foreach(func(k, v *ast.Term) {
				obj.Insert(k, v)
			})
			obj.Insert(key, value)
			return ast.NewTerm(obj), nil
		case *ast.Array:
			idx, err := toIndex(original, key)
			if err != nil || idx < 0 || idx > original.Len() {
				return nil, nil
			}
			arr := ast.NewArray()
			for i := 0; i < idx; i++ {
				arr = arr.Append(original.Elem(i))
			}
			arr = arr.Append(value)
			for i := idx; i < original.Len(); i++ {
				arr = arr.Append(original.Elem(i))
			}
			return ast.NewTerm(arr), nil
		case ast.Set:
			if !key.Equal(value) {
				return nil, nil
			}
			set := ast.NewSet()
			original.Foreach(func(k *ast.Term) {
				set.Add(k)
			})
			set.Add(key)
			return ast.NewTerm(set), nil
		}
		return nil, nil
	})

	return target
}

func jsonPatchRemove(target *ast.Term, path ast.Ref) (*ast.Term, *ast.Term) {
	// Special case: replacing root document.
	if len(path) == 0 {
		return nil, nil
	}

	target, removed := jsonPatchTraverse(target, path, func(parent *ast.Term, key *ast.Term) (*ast.Term, *ast.Term) {
		var removed *ast.Term
		switch original := parent.Value.(type) {
		case ast.Object:
			obj := ast.NewObject()
			original.Foreach(func(k, v *ast.Term) {
				if k.Equal(key) {
					removed = v
				} else {
					obj.Insert(k, v)
				}
			})
			return ast.NewTerm(obj), removed
		case *ast.Array:
			idx, err := toIndex(original, key)
			if err != nil || idx < 0 || idx >= original.Len() {
				return nil, nil
			}
			arr := ast.NewArray()
			for i := 0; i < idx; i++ {
				arr = arr.Append(original.Elem(i))
			}
			removed = original.Elem(idx)
			for i := idx + 1; i < original.Len(); i++ {
				arr = arr.Append(original.Elem(i))
			}
			return ast.NewTerm(arr), removed
		case ast.Set:
			set := ast.NewSet()
			original.Foreach(func(k *ast.Term) {
				if k.Equal(key) {
					removed = k
				} else {
					set.Add(k)
				}
			})
			return ast.NewTerm(set), removed
		}
		return nil, nil
	})

	if target != nil && removed != nil {
		return target, removed
	}

	return nil, nil
}

func jsonPatchReplace(target *ast.Term, path ast.Ref, value *ast.Term) *ast.Term {
	// Special case: replacing the whole document.
	if len(path) == 0 {
		return value
	}

	// Replace is specified as `remove` followed by `add`.
	if target, _ = jsonPatchRemove(target, path); target == nil {
		return nil
	}

	return jsonPatchAdd(target, path, value)
}

func jsonPatchMove(target *ast.Term, path ast.Ref, from ast.Ref) *ast.Term {
	// Move is specified as `remove` followed by `add`.
	target, removed := jsonPatchRemove(target, from)
	if target == nil || removed == nil {
		return nil
	}

	return jsonPatchAdd(target, path, removed)
}

func jsonPatchCopy(target *ast.Term, path ast.Ref, from ast.Ref) *ast.Term {
	value := jsonPatchGet(target, from)
	if value == nil {
		return nil
	}

	return jsonPatchAdd(target, path, value)
}

func jsonPatchTest(target *ast.Term, path ast.Ref, value *ast.Term) *ast.Term {
	actual := jsonPatchGet(target, path)
	if actual == nil {
		return nil
	}

	if actual.Equal(value) {
		return target
	}

	return nil
}

// Data structure notes:
// unsatKeys lets us crawl from back-to-front to find unsatisfied dependencies.
// activeHeads keeps track of the frontmost ops in the chain(s) that may exist.
//     It is updated each time patchChainDAG updates.
// satisfiedKeys lets us know which keys are guaranteed to be satisfied by 1+ ops later.
//     Diffing with unsatKeys allows us to see which keys only need to be tested for optimized-away ops.
// patchChainDAG is the front-to-back orderings of independent ops that we must do to satisfy the patch list.
//     It is constructed sequentially during the back-to-front crawl for unsatKeys, by adding items to the DAG each time they're removed from unsatKeys.
//

type PatchSeqDAG struct {
	unsatKeys     map[string][]int // key -> list of dependent patch idxs
	satKeys       map[string]int   // key -> satisfying patch idx
	activeHeads   map[int]struct{} // active patch idx set
	patchChainDAG map[int][]int    // massive patch list (nil = unused, [int...] = next patch idxs for that idx)
}

func NewPatchSeqDAG() PatchSeqDAG {
	var out PatchSeqDAG
	out.unsatKeys = map[string][]int{}
	out.satKeys = map[string]int{}
	out.activeHeads = map[int]struct{}{}
	out.patchChainDAG = map[int][]int{}
	return out
}

type jsonPatch struct {
	op    string
	path  string
	from  string
	value *ast.Term
}

func (psd *PatchSeqDAG) addUnsat(key string, index int) {
	ks, ok := psd.unsatKeys[key]
	if ok {
		// bail out early if index present.
		for i := range ks {
			if ks[i] == index {
				return
			}
		}
	}
	// Otherwise, add index to unsat list for the key.
	psd.unsatKeys[key] = append(psd.unsatKeys[key], index)
}

func (psd *PatchSeqDAG) delUnsat(key string) ([]int, bool) {
	ks, ok := psd.unsatKeys[key]
	delete(psd.unsatKeys, key)
	return ks, ok
}

// Constructs the PatchSeqDAG data structure we use to find the meaningful patch chains.
func BuildPatchSeqDAG(operations *ast.Array) (*PatchSeqDAG, error) {
	out := NewPatchSeqDAG()
	for i := operations.Len() - 1; i >= 0; i-- {
		var object ast.Object
		var ok bool
		object, ok = operations.Elem(i).Value.(ast.Object)
		if !ok {
			return nil, fmt.Errorf("must be an array of JSON-Patch objects, but element at index %d is not an object", i)
		}
		// TODO: Add array/sets to allowed "path" types for patches.
		patch, err := getPatch(object)
		if err != nil {
			return nil, err
		}

		switch patch.op {
		case "add":
			// TODO: Add a sweeping check for downstream paths that we're satisfying?
			if ks, ok := out.delUnsat(patch.path); ok {
				out.patchChainDAG[i] = ks
				// Move up active head to this patch.
				out.activeHeads[i] = struct{}{}
				for idx := range ks {
					delete(out.activeHeads, idx)
				}
			} else {
				out.patchChainDAG[i] = []int{i}
			}
			// If key not already registered, mark us as the last actor on this key.
			if _, ok := out.satKeys[patch.path]; !ok {
				out.satKeys[patch.path] = i
				out.activeHeads[i] = struct{}{}
			}
			// Add parent key to unsat keys:
			if parent, ok := getPathPrefix(patch.path); ok {
				out.addUnsat(parent, i)
			}
			//target = jsonPatchAdd(target, path, value)
		case "remove":
			// TODO: Add a sweeping check for downstream paths that we're breaking?
			// If there are dependent patches downstream of us that we are specifically breaking, we can error out early.
			if ks, ok := out.delUnsat(patch.path); ok {
				return nil, fmt.Errorf("patch at index %d with op 'remove' breaks patches at indexes %v", i, ks)
			}
			out.patchChainDAG[i] = []int{i}
			// If key not already registered, mark us as the last actor on this key.
			if _, ok := out.satKeys[patch.path]; !ok {
				out.satKeys[patch.path] = i
				out.activeHeads[i] = struct{}{} // TODO: Is this the correct spot for this?
			}
			// TODO: Should we also depend on the parent key?
			// Add the key we're deleting to the unsat keys:
			out.addUnsat(patch.path, i)
			//target, _ = jsonPatchRemove(target, path)
		case "replace":
			if ks, ok := out.delUnsat(patch.path); ok {
				return nil, fmt.Errorf("patch at index %d with op 'replace' breaks patches at indexes %v", i, ks)
			}
			out.patchChainDAG[i] = []int{i}
			// If key not already registered, mark us as the last actor on this key.
			if _, ok := out.satKeys[patch.path]; !ok {
				out.satKeys[patch.path] = i
				out.activeHeads[i] = struct{}{}
			}
			// TODO: Add parent key to unsat keys?
			out.addUnsat(patch.path, i)
			//target = jsonPatchReplace(target, path, value)
		case "move":
			// If there are dependent patches downstream of us that we are specifically breaking, we can error out early.
			if ks, ok := out.delUnsat(patch.from); ok {
				return nil, fmt.Errorf("patch at index %d with op 'move' breaks patches at indexes %v", i, ks)
			}
			// Handle everything downstream of us that this op satisfies.
			if ks, ok := out.delUnsat(patch.path); ok {
				out.patchChainDAG[i] = ks
				// Move up active head to this patch.
				out.activeHeads[i] = struct{}{}
				for idx := range ks {
					delete(out.activeHeads, idx)
				}
			} else {
				out.patchChainDAG[i] = []int{i}
			}
			// If key not already registered, mark us as the last actor on this key.
			if _, ok := out.satKeys[patch.path]; !ok {
				out.satKeys[patch.path] = i
				out.activeHeads[i] = struct{}{}
			}
			// Add the key we're moving to the unsat keys:
			out.addUnsat(patch.from, i)
			//target = jsonPatchMove(target, path, from)
		case "copy":
			// Handle everything downstream of us that this op satisfies.
			if ks, ok := out.delUnsat(patch.path); ok {
				out.patchChainDAG[i] = ks
				// Move up active head to this patch.
				out.activeHeads[i] = struct{}{}
				for idx := range ks {
					delete(out.activeHeads, idx)
				}
			} else {
				out.patchChainDAG[i] = []int{i}
			}
			// If key not already registered, mark us as the last actor on this key.
			if _, ok := out.satKeys[patch.path]; !ok {
				out.satKeys[patch.path] = i
				out.activeHeads[i] = struct{}{}
			}
			// Add the key we're copying to the unsat keys:
			out.addUnsat(patch.from, i)
			//target = jsonPatchCopy(target, path, from)
		case "test":
			out.patchChainDAG[i] = []int{i}
			// If key not already registered, mark us as the last actor on this key.
			if _, ok := out.satKeys[patch.path]; !ok {
				out.satKeys[patch.path] = i
				out.activeHeads[i] = struct{}{}
			}
			// Add the key we're testing to the unsat keys:
			out.addUnsat(patch.path, i)
			//target = jsonPatchTest(target, path, value)
		default:
			return nil, fmt.Errorf("must be an array of JSON-Patch objects")
		}
	}

	return &out, nil
}

// Trims the last chunk off of the JSON path.
// Used to generate "parent paths" for the unsat system.
// TODO: Actually write this logic in!
func getPathPrefix(jsonPath string) (string, bool) {
	parts := strings.Split(string(jsonPath), "/")
	if len(parts)-2 > 0 {
		return strings.Join(parts[:len(parts)-2], "/"), true
	}
	return "", false
}

// Generates a list of path suffixes the value satisfies.
// TODO: Actually write this logic in!
func getPathSuffixes(t *ast.Term) ([]string, error) {
	return []string{}, nil
}

func getPatch(o ast.Object) (jsonPatch, error) {
	var out jsonPatch
	var ok bool
	getAttribute := func(attr string) (*ast.Term, error) {
		if term := o.Get(ast.StringTerm(attr)); term != nil {
			return term, nil
		}

		return nil, fmt.Errorf("missing '%s' attribute", attr)
	}

	opTerm, err := getAttribute("op")
	if err != nil {
		return out, err
	}
	op, ok := opTerm.Value.(ast.String)
	if !ok {
		return out, fmt.Errorf("attribute 'op' must be a string")
	}
	out.op = string(op)

	pathTerm, err := getAttribute("path")
	if err != nil {
		return out, err
	}
	path, ok := pathTerm.Value.(ast.String)
	if !ok {
		return out, fmt.Errorf("attribute 'path' must be a string")
	}
	out.path = string(path)

	// Fetch if present:
	if fromTerm, err := getAttribute("from"); err == nil {
		from, ok := fromTerm.Value.(ast.String)
		if !ok {
			return out, fmt.Errorf("attribute 'from' must be a string")
		}
		out.from = string(from)
	}

	// Fetch if present:
	if valueTerm, err := getAttribute("value"); err == nil {
		out.value = valueTerm
	}

	return out, nil
}

// Need:
// - GetXprop() funcs
// - Get

// TODO: May want to delete the whole record, and return the values slice.
//
//	func (psd *PatchSeqDAG) delUnsat(string key, index int) {
//		ks, ok := psd.unsatKeys[key];
//		if ok {
//			// bail out early if index present.
//			for i := range ks {
//				if ks[i] == index {
//					psd.unsatKeys[key] = append(ks[:i], ks[i+1:])
//					break
//				}
//			}
//		}
//		// Wipe out the key if no entries remain.
//		if len(psd.unsatKeys[key]) == 0 {
//			delete(psd.unsatKeys, key)
//		}
//	}

func builtinJSONPatch(_ BuiltinContext, operands []*ast.Term, iter func(*ast.Term) error) error {
	// JSON patch supports arrays, objects as well as values as the target.
	target := ast.NewTerm(operands[0].Value)

	// Expect an array of operations.
	operations, err := builtins.ArrayOperand(operands[1].Value, 2)
	if err != nil {
		return err
	}

	// Apply operations one by one.
	for i := 0; i < operations.Len(); i++ {
		if object, ok := operations.Elem(i).Value.(ast.Object); ok {
			getAttribute := func(attr string) (*ast.Term, error) {
				if term := object.Get(ast.StringTerm(attr)); term != nil {
					return term, nil
				}

				return nil, builtins.NewOperandErr(2, fmt.Sprintf("patch is missing '%s' attribute", attr))
			}

			getPathAttribute := func(attr string) (ast.Ref, error) {
				term, err := getAttribute(attr)
				if err != nil {
					return ast.Ref{}, err
				}
				path, err := parsePath(term)
				if err != nil {
					return ast.Ref{}, err
				}
				return path, nil
			}

			// Parse operation.
			opTerm, err := getAttribute("op")
			if err != nil {
				return err
			}
			op, ok := opTerm.Value.(ast.String)
			if !ok {
				return builtins.NewOperandErr(2, "patch attribute 'op' must be a string")
			}

			// Parse path.
			path, err := getPathAttribute("path")
			if err != nil {
				return err
			}

			switch op {
			case "add":
				value, err := getAttribute("value")
				if err != nil {
					return err
				}
				target = jsonPatchAdd(target, path, value)
			case "remove":
				target, _ = jsonPatchRemove(target, path)
			case "replace":
				value, err := getAttribute("value")
				if err != nil {
					return err
				}
				target = jsonPatchReplace(target, path, value)
			case "move":
				from, err := getPathAttribute("from")
				if err != nil {
					return err
				}
				target = jsonPatchMove(target, path, from)
			case "copy":
				from, err := getPathAttribute("from")
				if err != nil {
					return err
				}
				target = jsonPatchCopy(target, path, from)
			case "test":
				value, err := getAttribute("value")
				if err != nil {
					return err
				}
				target = jsonPatchTest(target, path, value)
			default:
				return builtins.NewOperandErr(2, "must be an array of JSON-Patch objects")
			}
		} else {
			return builtins.NewOperandErr(2, "must be an array of JSON-Patch objects")
		}

		// JSON patches should work atomically; and if one of them fails,
		// we should not try to continue.
		if target == nil {
			return nil
		}
	}

	return iter(target)
}

func init() {
	RegisterBuiltinFunc(ast.JSONFilter.Name, builtinJSONFilter)
	RegisterBuiltinFunc(ast.JSONRemove.Name, builtinJSONRemove)
	RegisterBuiltinFunc(ast.JSONPatch.Name, builtinJSONPatch)
}
