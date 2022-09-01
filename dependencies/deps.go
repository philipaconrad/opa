// Copyright 2017 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package dependencies

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"git.sr.ht/~charles/graph"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/internal/ir"
	"github.com/open-policy-agent/opa/util"
)

// Computational complexity:
// - CFG Construction: O(N) (at a minimum)
// - CFG Path walking: O(2^B), where B is the number of branches.

// To do dependency analysis properly, we need to walk *every* path through the program.
// For this, we construct the control-flow graph (CFG) of the program, and then traverse *every* path through that directed acyclic graph (DAG).
// This requires us to first put together a good graph. Thankfully, ~charles/graph is an available graph module for this purpose.
// CFG construction / walking:
// - Each function, plan, and block in the program is first given a unique name (referred to as its "address").
// - We then create unique graph nodes for the beginning and end of each function, plan, and block, and track the map of names -> nodes for later. ("landmarks" map)
//   - Landmark names look like:
//     - plans:               "plans.policy/allow$begin", "plans.policy/allow$end"
//     - blocks in functions: "funcs.g0.data.policy.allow.b0$begin", "funcs.g0.data.policy.allow.b0$end"
//     - sub-blocks:          "funcs.g0.data.policy.allow.0:2.1$begin" (block 0, statement 2, block 1, begin)
//     - This makes it trivial to string together the default control paths between blocks, and to know what to target.
// --> The above 2x steps look like:  getLandmarks(policy) (map[string]int, Graph)
// - We then walk through the policy linearly from the top down, and begin adding nodes to the graph for statements, and edges to mark control flow. (customized for Torin's dependencies use case?)
// --> The above step looks like:     addStmtsToGraph(policy, landmarks, graph) (Graph)
// - Once the CFG is finished, we iteratively evaluate the stmt chain along every path, doing simple bookkeeping on the locals we see.
//   - Sets of refs seen along each path can be bulk-union'd at the end and returned.

// Extracts the landmarks map and an initial graph from the policy.
// Does at least block-level graph construction, might go statement level if needed.
func getLandmarks(p *ir.Policy) (map[string]graph.Node, *graph.Graph) {
	landmarks := map[string]graph.Node{}
	out := graph.NewGraph()

	rootNode := out.NewNodeWithData("start")
	landmarks["start"] = rootNode

	// Add plans to landmarks.
	for i := range p.Plans.Plans {
		plan := p.Plans.Plans[i]
		planName := "plans." + plan.Name
		beginNode := out.NewNodeWithData(planName + "$begin")
		endNode := out.NewNodeWithData(planName + "$end")
		landmarks[planName+"$begin"] = beginNode
		landmarks[planName+"$end"] = endNode
		out.NewEdgeWithData(rootNode, beginNode, nil)
	}

	// Add functions to landmarks.
	for i := range p.Funcs.Funcs {
		plan := p.Funcs.Funcs[i]
		funcName := "funcs." + plan.Name
		beginNode := out.NewNodeWithData(funcName + "$begin")
		endNode := out.NewNodeWithData(funcName + "$end")
		landmarks[funcName+"$begin"] = beginNode
		landmarks[funcName+"$end"] = endNode
	}

	// Add plan blocks recursively to landmarks.
	for i := range p.Plans.Plans {
		plan := p.Plans.Plans[i]
		// Ensure first block is stitched up to the start-of-plan.
		prevNode := landmarks["plans."+plan.Name+"$begin"]
		for j := range plan.Blocks {
			block := plan.Blocks[j]
			blockName := "plans." + plan.Name + "." + strconv.Itoa(j)
			beginNode := out.NewNodeWithData(blockName + "$begin")
			endNode := out.NewNodeWithData(blockName + "$end")
			// Stitch each end-of-block to next start-of-block.
			out.NewEdgeWithData(prevNode, beginNode, nil)
			prevNode = endNode
			addStmtsNodesEdges(block, blockName, landmarks, out)
		}
		// Stitch the last end-of-block -> end-of-plan.
		out.NewEdgeWithData(prevNode, landmarks["plans."+plan.Name+"$end"], nil)
	}

	return landmarks, out
}

// In-place modifies the graph.
// General flow for each statement type is:
//  - Create node for that stmt.
//  - Link end from current stmt to the stmt before it.
//  - Optional:
//    - Generate any additional out edges (break, call, etc.)
//    - Recurse into sub-blocks.
func addStmtsNodesEdges(block *ir.Block, parentAddr string, landmarks map[string]graph.Node, g *graph.Graph) {
	var prevNodeName = parentAddr + "$begin"
	for i := range block.Stmts {
		stmt := block.Stmts[i]
		// Create node.
		node := g.NewNodeWithData(stmt)
		nodeName := parentAddr + ":" + strconv.Itoa(i)
		landmarks[nodeName] = node
		// Link to prior stmt node. (special case for first stmt in block.)
		g.NewEdgeWithData(landmarks[prevNodeName], node, nil)
		prevNodeName = nodeName
		// Do special optional work, depending on stmt type:
		switch x := stmt.(type) {
		case *ir.ReturnLocalStmt:
			// Skip end-of-block stitching, we're bailing.
			g.NewEdgeWithData(node, landmarks[parentAddr+"$end"], nil)
			return
		case *ir.CallStmt:
			// Link out to the correct function.
			if strings.HasPrefix(x.Func, "internal.") {
				// no-op for now!
				// TODO(philipc): Let's fix this when we know how to handle builtin calls.
			} else {
				funcName := "funcs." + x.Func
				// Out edge to the function.
				g.NewEdgeWithData(node, landmarks[funcName+"$begin"], nil)
				// Return edge should be from end-of-func.
				prevNodeName = "funcs." + x.Func + "$end"
				continue
			}
		case *ir.CallDynamicStmt:
			// no-op for now!
			// TODO(philipc): Let's fix this when we know how to handle this type of dynamic call.
		case *ir.BlockStmt:
			for j := range x.Blocks {
				addStmtsNodesEdges(x.Blocks[j], nodeName, landmarks, g)
			}
		case *ir.BreakStmt:
			levels := x.Index
			path := strings.Split(parentAddr, ".")
			// Don't duplicate end-of-block stitching.
			if levels == 0 {
				g.NewEdgeWithData(node, landmarks[parentAddr+"$end"], nil)
				return
			} else {
				// TODO(philipc): Add some validation either here or elsewhere to ensure we don't jump too high.
				breakPath := path[:len(path)-int(levels)]
				breakDestName := strings.Join(breakPath, ".")
				//isnumeric check? determines whether to tag $begin/$end, or else iter by one, and paste in the $begin/$end
				g.NewEdgeWithData(node, landmarks[breakDestName+"$end"], nil) // TODO: Verify this is right.
				return
			}
		case *ir.DotStmt:
			// Defined/Undefined branches.
			g.NewEdgeWithData(node, landmarks[parentAddr+"$end"], nil) // Undefined branch.
		case *ir.LenStmt:
		case *ir.ScanStmt:
			addStmtsNodesEdges(x.Block, nodeName, landmarks, g)
			// Defined/Undefined branches.
			g.NewEdgeWithData(node, landmarks[parentAddr+"$end"], nil) // Undefined branch.
		case *ir.NotStmt:
			addStmtsNodesEdges(x.Block, nodeName, landmarks, g)
			// Defined/Undefined branches.
			g.NewEdgeWithData(node, landmarks[parentAddr+"$end"], nil) // Undefined branch.
		case *ir.AssignIntStmt:
		case *ir.AssignVarStmt:
		case *ir.AssignVarOnceStmt:
		case *ir.ResetLocalStmt:
		case *ir.MakeNullStmt:
		case *ir.MakeNumberIntStmt:
		case *ir.MakeNumberRefStmt:
		case *ir.MakeArrayStmt:
		case *ir.MakeObjectStmt:
		case *ir.MakeSetStmt:
		case *ir.EqualStmt:
			// Defined/Undefined branches.
			g.NewEdgeWithData(node, landmarks[parentAddr+"$end"], nil) // Undefined branch.
		case *ir.NotEqualStmt:
			// Defined/Undefined branches.
			g.NewEdgeWithData(node, landmarks[parentAddr+"$end"], nil) // Undefined branch.
		case *ir.IsArrayStmt:
			// Defined/Undefined branches.
			g.NewEdgeWithData(node, landmarks[parentAddr+"$end"], nil) // Undefined branch.
		case *ir.IsObjectStmt:
			// Defined/Undefined branches.
			g.NewEdgeWithData(node, landmarks[parentAddr+"$end"], nil) // Undefined branch.
		case *ir.IsDefinedStmt:
			// Defined/Undefined branches.
			g.NewEdgeWithData(node, landmarks[parentAddr+"$end"], nil) // Undefined branch.
		case *ir.IsUndefinedStmt:
			// Defined/Undefined branches.
			g.NewEdgeWithData(node, landmarks[parentAddr+"$end"], nil) // Undefined branch.
		case *ir.ArrayAppendStmt:
		case *ir.ObjectInsertStmt:
		case *ir.ObjectInsertOnceStmt:
		case *ir.ObjectMergeStmt:
		case *ir.SetAddStmt:
		case *ir.WithStmt:
			addStmtsNodesEdges(x.Block, nodeName, landmarks, g)
		case *ir.NopStmt:
		case *ir.ResultSetAddStmt:
		}
	}
	// Stitch up last statement to end-of-block.
	g.NewEdgeWithData(landmarks[prevNodeName], landmarks[parentAddr+"$end"], nil)
}

// type executionResult enum {
// 	branchForDefUndef <implicit: null ret> <implicit: next stmt>
//  breakNLevels N
//  return
//  return with value V
//  next <implict: next stmt>
//  blocks
//  block
//  call
//  calldyn?
// }

// OR! consider:
// {
// X- type enum
// - breakLevels int
// X- callTarget
// X- callDynTarget (maybe ignore at first?)
// }
// Then, if the ptr is nil, we can ignore, and do the sane thing.
// Otherwise, we've got a non-local control thing happening!
// Maybe just return a pointer to an int? If it's nil, we know we've got no breaks happening.
// - If it's 0, then we know we just hit the level we should be on.
// - If it's 1+, then we know we should just return upwards (we're in a recursive chain of some kind).
// - This means we can safely let blocks see their neighbors! Non-local breaks imply that somebody higher up will figure stuff out.

// // I'm wondering if we should include the possibility for custom "function" and "block" handler functions to be provided.
// // Those would allow custom handling of nested blocks/functions, but maybe it's a dumb idea.

// func copyLocalRefs(x map[int]string) map[int]string {
// 	out := make(map[int]string, len(x))
// 	for k, v := range x {
// 		out[k] = v
// 	}
// 	return out
// }

// func copyLocalDeps(x map[int]ast.Set) map[int]ast.Set {
// 	out := make(map[int]ast.Set, len(x))
// 	for k, v := range x {
// 		out[k] = v.Copy()
// 	}
// 	return out
// }

// type blockList struct {
// 	blocks []*ir.Block
// 	index  int
// }

// type blockStack struct {
// 	v []*blockList
// }

// func (bs *blockStack) push(bl *blockList) {
// 	bs.v = append(bs.v, bl)
// }

// func (bs *blockStack) pop() *blockList {
// 	if len(bs.v) > 0 {
// 		endIndex := len(bs.v) - 1
// 		out, stack := bs.v[endIndex], bs.v[:endIndex]
// 		bs.v = stack
// 		return out
// 	}
// 	return nil
// }

// // analyzeBlock iterates through each statement in the block, recursing on branches and calls as needed.
// // The final bundle of dependency sets is union'd together, and returned upwards, along with locals and control-flow info.
// // We handle breaks by using the block address + blockList to allow us to figure out the place to pick up execution.
// // - Block list is the original block list of the function/plan
// // - Address is an []{int, int} that we can use to dive down to the correct level by indexing the correct block, then statement within the block?
// // - Or is address as []int sufficiently unambiguous? I'd hope so.
// // - Perhaps a better approach is appending a pointer to the parent blocklist each time we dive down a level?

// // Evaluate all paths through the program, rooted at this blocklist, with this incoming state.
// func analyzeBlockList?

// // Trace the path of
// func traceDepsFromStmt() () {

// }

// // Evaluate all paths through the program, rooted at this block, with this incoming state.
// func analyzeBlock(
// 	policy *ir.Policy,
// 	block *ir.Block,
// 	blocks *blockStack,
// 	localRefs map[int]string,
// 	localDeps map[int]ast.Set) (*blockStack, map[int]string, map[int]ast.Set, ast.Set) {
// 	globalDeps := ast.NewSet()
// 	var seenDeps ast.Set
// 	var localR = localRefs
// 	var localD = localDeps
// 	var bs = blocks

// 	for _, stmt := range block.Stmts {
// 		bs, localR, localD, seenDeps = analyzeStmt(policy, &stmt, copyLocalRefs(localR), copyLocalDeps(localD))
// 		globalDeps = globalDeps.Union(seenDeps)
// 	}

// 	return bs, localR, localD, seenDeps
// }

// // Evaluate all paths through the program, rooted at this statement, with this incoming state.
// func analyzeStmt(
// 	policy *ir.Policy,
// 	stmt *ir.Stmt,
// 	localRefs map[int]string,
// 	localDeps map[int]ast.Set) (*blockStack, map[int]string, map[int]ast.Set, ast.Set) {
// 	iStmt := *stmt

// 	switch iStmt.(type) {
// 	case *ir.ReturnLocalStmt:
// 	case *ir.CallStmt:
// 	case *ir.CallDynamicStmt:
// 	case *ir.BlockStmt:
// 	case *ir.BreakStmt:
// 	case *ir.DotStmt:
// 	case *ir.LenStmt:
// 	case *ir.ScanStmt:
// 	case *ir.NotStmt:
// 	case *ir.AssignIntStmt:
// 	case *ir.AssignVarStmt:
// 	case *ir.AssignVarOnceStmt:
// 	case *ir.ResetLocalStmt:
// 	case *ir.MakeNullStmt:
// 	case *ir.MakeNumberIntStmt:
// 	case *ir.MakeNumberRefStmt:
// 	case *ir.MakeArrayStmt:
// 	case *ir.MakeObjectStmt:
// 	case *ir.MakeSetStmt:
// 	case *ir.EqualStmt:
// 	case *ir.NotEqualStmt:
// 	case *ir.IsArrayStmt:
// 	case *ir.IsObjectStmt:
// 	case *ir.IsDefinedStmt:
// 	case *ir.IsUndefinedStmt:
// 	case *ir.ArrayAppendStmt:
// 	case *ir.ObjectInsertStmt:
// 	case *ir.ObjectInsertOnceStmt:
// 	case *ir.ObjectMergeStmt:
// 	case *ir.SetAddStmt:
// 	case *ir.WithStmt:
// 	case *ir.NopStmt:
// 	case *ir.ResultSetAddStmt:
// 	}
// }

// // We need to build a CFG to be able to evaluate the transfer functions along each possible execution path
// // for dependency analysis. It sucks, but this is one of the easiest ways to get that information.
// // Once the CFG is constructed, every statement should be in one or more graph paths.
// // We can then begin a recursive graph traversal, hitting all paths to the end.
// // Along the way, we can implicitly evaluate the transfer functions of each statement.

// type policyDepCtx struct {
// 	policy       *ir.Policy
// 	callstack    []int           // Block indices. Each nesting level deeper appends a new int.
// 	dependencies ast.Set         // Tracks all unique dependencies seen in the policy.
// 	localRefs    map[int]string  // Tracks dotted ref names, per local register.
// 	localDeps    map[int]ast.Set // Tracks all refs affecting a local register.
// }

// func (p *policyDepCtx) Copy() *policyDepCtx {
// 	out := &policyDepCtx{}
// 	out.policy = p.policy
// 	out.callstack = make([]int, len(p.callstack))
// 	copy(out.callstack, p.callstack)
// 	out.dependencies = p.dependencies.Copy()
// 	out.localDeps = make(map[int]ast.Set, len(p.localDeps))
// 	for k, v := range p.localDeps {
// 		out.localDeps[k] = v
// 	}
// 	out.localRefs = make(map[int]string, len(p.localRefs))
// 	for k, v := range p.localRefs {
// 		out.localRefs[k] = v
// 	}
// 	return out
// }

// func (p *policyDepCtx) pushCallStack(v int) {
// 	p.callstack = append(p.callstack, v)
// }

// // Can panic, unfortunately.
// func (p *policyDepCtx) popCallStack() int {
// 	out := p.callstack[len(p.callstack)-1]
// 	p.callstack = p.callstack[0 : len(p.callstack)-1]
// 	return out
// }

// func FindExternalDeps(sourceModules, entrypointQueries []string) (ast.Set, error) {
// 	queries := make([]ast.Body, len(entrypointQueries))
// 	for i := range queries {
// 		queries[i] = ast.MustParseBody(entrypointQueries[i])
// 	}
// 	modules := make([]*ast.Module, len(sourceModules))
// 	for i := range modules {
// 		file := fmt.Sprintf("module-%d.rego", i)
// 		m, err := ast.ParseModule(file, sourceModules[i])
// 		if err != nil {
// 			return nil, err
// 		}
// 		modules[i] = m
// 	}
// 	planner := planner.New().WithQueries([]planner.QuerySet{
// 		{
// 			Name:    "test",
// 			Queries: queries,
// 		},
// 	}).WithModules(modules).WithBuiltinDecls(ast.BuiltinMap)
// 	policy, err := planner.Plan()
// 	if err != nil {
// 		return nil, err
// 	}
// 	return ast.NewSet(), nil
// }

// func trackDepsInPlan(p ir.Plan, gDC *policyDepCtx) (*policyDepCtx, error) {
// 	var err error
// 	outGDC := gDC.Copy()
// 	outGDC, err = trackDepsInBlocks(p.Blocks, outGDC)
// 	return outGDC, err
// }

// func trackDepsInFunction(f ir.Func, gDC *policyDepCtx) (*policyDepCtx, error) {
// 	var err error
// 	outGDC := gDC.Copy()
// 	outGDC, err = trackDepsInBlocks(f.Blocks, outGDC)
// 	return outGDC, err
// }

// func trackDepsInBlocks(blocks []*ir.Block, gDC *policyDepCtx) (*policyDepCtx, error) {
// 	var err error
// 	outGDC := gDC.Copy()
// 	for i, block := range blocks {
// 		outGDC.pushCallStack(i)
// 		outGDC, err = trackDepsInBlock(block, blocks, outGDC)
// 		if err != nil {
// 			return nil, err
// 		}
// 		outGDC.popCallStack()
// 	}
// 	return outGDC, nil
// }

// func trackDepsInBlock(block *ir.Block, parentBlocks []*ir.Block, gDC *policyDepCtx) (*policyDepCtx, error) {
// 	var err error
// 	outGDC := gDC.Copy()
// 	for _, stmt := range block.Stmts {
// 		outGDC, err = trackDepsInStmt(stmt, gDC)
// 		if err != nil {
// 			return nil, err
// 		}

// 	}
// 	return outGDC, nil
// }

// func trackDepsInStmt(stmt ir.Stmt, gDC *policyDepCtx) (*policyDepCtx, error) {
// 	iStmt := stmt
// 	switch iStmt.(type) {
// 	case *ir.ReturnLocalStmt:
// 	case *ir.CallStmt:
// 	case *ir.CallDynamicStmt:
// 	case *ir.BlockStmt:
// 	case *ir.BreakStmt:
// 	case *ir.DotStmt:
// 	case *ir.LenStmt:
// 	case *ir.ScanStmt:
// 	case *ir.NotStmt:
// 	case *ir.AssignIntStmt:
// 	case *ir.AssignVarStmt:
// 	case *ir.AssignVarOnceStmt:
// 	case *ir.ResetLocalStmt:
// 	case *ir.MakeNullStmt:
// 	case *ir.MakeNumberIntStmt:
// 	case *ir.MakeNumberRefStmt:
// 	case *ir.MakeArrayStmt:
// 	case *ir.MakeObjectStmt:
// 	case *ir.MakeSetStmt:
// 	case *ir.EqualStmt:
// 	case *ir.NotEqualStmt:
// 	case *ir.IsArrayStmt:
// 	case *ir.IsObjectStmt:
// 	case *ir.IsDefinedStmt:
// 	case *ir.IsUndefinedStmt:
// 	case *ir.ArrayAppendStmt:
// 	case *ir.ObjectInsertStmt:
// 	case *ir.ObjectInsertOnceStmt:
// 	case *ir.ObjectMergeStmt:
// 	case *ir.SetAddStmt:
// 	case *ir.WithStmt:
// 	case *ir.NopStmt:
// 	case *ir.ResultSetAddStmt:
// 	}

// }

// All returns the list of data ast.Refs that the given AST element depends on.
func All(x interface{}) (resolved []ast.Ref, err error) {
	var rawResolved []ast.Ref
	switch x := x.(type) {
	case *ast.Module, *ast.Package, *ast.Import, *ast.Rule, *ast.Head, ast.Body, *ast.Expr, *ast.With, *ast.Term, ast.Ref, ast.Object, *ast.Array, ast.Set, *ast.ArrayComprehension:
	default:
		return nil, fmt.Errorf("not an ast element: %v", x)
	}

	visitor := ast.NewGenericVisitor(func(x interface{}) bool {
		switch x := x.(type) {
		case *ast.Package, *ast.Import:
			return true
		case *ast.Module, *ast.Head, *ast.Expr, *ast.With, *ast.Term, ast.Object, *ast.Array, *ast.Set, *ast.ArrayComprehension:
		case *ast.Rule:
			rawResolved = append(rawResolved, ruleDeps(x)...)
			return true
		case ast.Body:
			vars := ast.NewVarVisitor()
			vars.Walk(x)

			arr := ast.NewArray()
			for v := range vars.Vars() {
				if v.IsWildcard() {
					continue
				}
				arr = arr.Append(ast.NewTerm(v))
			}

			// The analysis will discard variables that are not used in
			// direct comparisons or in the output. Since lone Bodies are
			// often queries, we want all the variables to be in the output.
			r := &ast.Rule{
				Head: &ast.Head{Name: ast.Var("_"), Value: ast.NewTerm(arr)},
				Body: x,
			}
			rawResolved = append(rawResolved, ruleDeps(r)...)
			return true
		case ast.Ref:
			rawResolved = append(rawResolved, x)
		}
		return false
	})
	visitor.Walk(x)
	if len(rawResolved) == 0 {
		return nil, nil
	}

	return dedup(rawResolved), nil
}

// Minimal returns the list of data ast.Refs that the given AST element depends on.
// If an AST element depends on a ast.Ref that is a prefix of another dependency, the
// ast.Ref that is the prefix of the other will be the only one in the returned list.
//
// As an example, if an element depends on data.x and data.x.y, only data.x will
// be in the returned list.
func Minimal(x interface{}) (resolved []ast.Ref, err error) {
	rawResolved, err := All(x)
	if err != nil {
		return nil, err
	}

	if len(rawResolved) == 0 {
		return nil, nil
	}

	return filter(rawResolved, func(a, b ast.Ref) bool {
		return b.HasPrefix(a)
	}), nil
}

// Base returns the list of base data documents that the given AST element depends on.
//
// The returned refs are always constant and are truncated at any point where they become
// dynamic. That is, a ref like data.a.b[x] will be truncated to data.a.b.
func Base(compiler *ast.Compiler, x interface{}) ([]ast.Ref, error) {
	baseRefs, err := base(compiler, x)
	if err != nil {
		return nil, err
	}

	return dedup(baseRefs), nil
}

func base(compiler *ast.Compiler, x interface{}) ([]ast.Ref, error) {
	refs, err := Minimal(x)
	if err != nil {
		return nil, err
	}

	var baseRefs []ast.Ref
	for _, r := range refs {
		r = r.ConstantPrefix()
		if rules := compiler.GetRules(r); len(rules) > 0 {
			for _, rule := range rules {
				bases, err := base(compiler, rule)
				if err != nil {
					panic("not reached")
				}

				baseRefs = append(baseRefs, bases...)
			}
		} else {
			baseRefs = append(baseRefs, r)
		}
	}

	return baseRefs, nil
}

// Virtual returns the list of virtual data documents that the given AST element depends
// on.
//
// The returned refs are always constant and are truncated at any point where they become
// dynamic. That is, a ref like data.a.b[x] will be truncated to data.a.b.
func Virtual(compiler *ast.Compiler, x interface{}) ([]ast.Ref, error) {
	virtualRefs, err := virtual(compiler, x)
	if err != nil {
		return nil, err
	}

	return dedup(virtualRefs), nil
}

func virtual(compiler *ast.Compiler, x interface{}) ([]ast.Ref, error) {
	refs, err := Minimal(x)
	if err != nil {
		return nil, err
	}

	var virtualRefs []ast.Ref
	for _, r := range refs {
		r = r.ConstantPrefix()
		if rules := compiler.GetRules(r); len(rules) > 0 {
			for _, rule := range rules {
				virtuals, err := virtual(compiler, rule)
				if err != nil {
					panic("not reached")
				}

				virtualRefs = append(virtualRefs, rule.Path())
				virtualRefs = append(virtualRefs, virtuals...)
			}
		}
	}

	return virtualRefs, nil
}

func dedup(refs []ast.Ref) []ast.Ref {
	sort.Slice(refs, func(i, j int) bool {
		return refs[i].Compare(refs[j]) < 0
	})

	return filter(refs, func(a, b ast.Ref) bool {
		return a.Compare(b) == 0
	})
}

// filter removes all items from the list that cause pref to return true. It is
// called on adjacent pairs of elements, and the one passed as the second argument
// to pref is considered the current one being examined. The first argument will
// be the element immediately preceding it.
func filter(rs []ast.Ref, pred func(ast.Ref, ast.Ref) bool) (filtered []ast.Ref) {
	if len(rs) == 0 {
		return nil
	}

	last := rs[0]
	filtered = append(filtered, last)
	for i := 1; i < len(rs); i++ {
		cur := rs[i]
		if pred(last, cur) {
			continue
		}

		filtered = append(filtered, cur)
		last = cur
	}

	return filtered
}

// FIXME(tsandall): this logic should be revisited as it seems overly
// complicated. It should be possible to compute all dependencies in two
// passes:
//
// 1) perform syntactic unification on vars
// 2) gather all refs rooted at data after plugging the head with substitution
//    from (1)
func ruleDeps(rule *ast.Rule) (resolved []ast.Ref) {
	vars, others := extractEq(rule.Body)
	joined := joinVarRefs(vars)

	headVars := rule.Head.Vars()
	headRefs, others := resolveOthers(others, headVars, joined)

	resolveRef := func(r ast.Ref) bool {
		resolved = append(resolved, expandRef(r, joined)...)
		return false
	}

	varVisitor := ast.NewVarVisitor().WithParams(ast.VarVisitorParams{SkipRefHead: true})
	// Clean up whatever refs are remaining among the other expressions.
	for _, expr := range others {
		ast.WalkRefs(expr, resolveRef)
		varVisitor.Walk(expr)
	}

	// If a reference ending in a header variable is a prefix of an already
	// resolved reference, skip it and simply walk the nodes below it.
	visitor := &skipVisitor{fn: resolveRef}
	for _, r := range headRefs {
		if !containsPrefix(resolved, r) {
			resolved = append(resolved, r.Copy())
		}
		visitor.skipped = false
		ast.NewGenericVisitor(visitor.Visit).Walk(r)
	}

	usedVars := varVisitor.Vars()

	// Vars included in refs must be counted as used.
	ast.WalkRefs(rule.Body, func(r ast.Ref) bool {
		for i := 1; i < len(r); i++ {
			if v, ok := r[i].Value.(ast.Var); ok {
				usedVars.Add(v)
			}
		}
		return false
	})

	resolveRemainingVars(joined, visitor, usedVars, headVars)
	return resolved
}

// Extract the equality expressions from each rule, they contain
// the potential split references. In order to be considered for
// joining, an equality must have a variable on one side and a
// reference on the other. Any other construct is thrown into
// the others list to be resolved later.
func extractEq(exprs ast.Body) (vars map[ast.Var][]ast.Ref, others []*ast.Expr) {
	vars = map[ast.Var][]ast.Ref{}
	for v := range exprs.Vars(ast.VarVisitorParams{}) {
		vars[v] = nil
	}

	for _, expr := range exprs {
		if !expr.IsEquality() {
			others = append(others, expr)
			continue
		}

		terms := expr.Terms.([]*ast.Term)
		left, right := terms[1], terms[2]
		if l, ok := left.Value.(ast.Var); ok {
			if r, ok := right.Value.(ast.Ref); ok {
				vars[l] = append(vars[l], r)
				continue
			}
		} else if r, ok := right.Value.(ast.Var); ok {
			if l, ok := left.Value.(ast.Ref); ok {
				vars[r] = append(vars[r], l)
				continue
			}
		}

		others = append(others, expr)
	}
	return vars, others
}

func expandRef(r ast.Ref, vars map[ast.Var]*util.HashMap) []ast.Ref {
	head, rest := r[0], r[1:]
	if ast.RootDocumentNames.Contains(head) {
		return []ast.Ref{r}
	}

	h := head.Value.(ast.Var)
	rs, ok := vars[h]
	if !ok {
		return nil
	}

	var expanded []ast.Ref
	rs.Iter(func(a, _ util.T) bool {
		ref := a.(ast.Ref)
		expanded = append(expanded, append(ref.Copy(), rest...))
		return false
	})
	return expanded
}

func joinVarRefs(vars map[ast.Var][]ast.Ref) map[ast.Var]*util.HashMap {
	joined := map[ast.Var]*util.HashMap{}
	for v := range vars {
		joined[v] = util.NewHashMap(refEq, refHash)
	}

	done := false
	for !done {
		done = true
		for v, rs := range vars {
			for _, r := range rs {
				head, rest := r[0], r[1:]
				if ast.RootDocumentNames.Contains(head) {
					if _, ok := joined[v].Get(r); !ok {
						joined[v].Put(r, struct{}{})
						done = false
					}
					continue
				}

				h, ok := head.Value.(ast.Var)
				if !ok {
					panic("not reached")
				}

				joined[h].Iter(func(a, _ util.T) bool {
					jr := a.(ast.Ref)
					join := append(jr.Copy(), rest...)
					if _, ok := joined[v].Get(join); !ok {
						joined[v].Put(join, struct{}{})
						done = false
					}
					return false
				})
			}
		}
	}

	return joined
}

func resolveOthers(others []*ast.Expr, headVars ast.VarSet, joined map[ast.Var]*util.HashMap) (headRefs []ast.Ref, leftover []*ast.Expr) {
	for _, expr := range others {
		if term, ok := expr.Terms.(*ast.Term); ok {
			if r, ok := term.Value.(ast.Ref); ok {
				end := r[len(r)-1]
				v, ok := end.Value.(ast.Var)
				if ok && headVars.Contains(v) {
					headRefs = append(headRefs, expandRef(r, joined)...)
					continue
				}
			}
		}

		leftover = append(leftover, expr)
	}

	return headRefs, leftover
}

func resolveRemainingVars(joined map[ast.Var]*util.HashMap, visitor *skipVisitor, usedVars ast.VarSet, headVars ast.VarSet) {
	for v, refs := range joined {
		skipped := false

		if headVars.Contains(v) || refs.Len() > 1 || usedVars.Contains(v) {
			skipped = true
		}

		refs.Iter(func(a, _ util.T) bool {
			visitor.skipped = skipped
			r := a.(ast.Ref)
			ast.NewGenericVisitor(visitor.Visit).Walk(r)
			return false
		})
	}
}

func containsPrefix(refs []ast.Ref, r ast.Ref) bool {
	for _, ref := range refs {
		if ref.HasPrefix(r) {
			return true
		}
	}
	return false
}

func refEq(a, b util.T) bool {
	ar, aok := a.(ast.Ref)
	br, bok := b.(ast.Ref)
	return aok && bok && ar.Equal(br)
}

func refHash(a util.T) int {
	return a.(ast.Ref).Hash()
}

type skipVisitor struct {
	fn      func(ast.Ref) bool
	skipped bool
}

func (sv *skipVisitor) Visit(v interface{}) bool {
	if sv.skipped {
		if r, ok := v.(ast.Ref); ok {
			return sv.fn(r)
		}
	}

	sv.skipped = true
	return false
}
