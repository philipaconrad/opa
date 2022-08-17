package graph

import (
	"fmt"
)

// Node represents a handle to a specific node in the graph. Nodes are
// immutable, and internally contain a node ID (referencing into the underlying
// data store), and a pointer the underlying graph.
type Node struct {
	id    int64
	graph *Graph
}

// ID returns the ID of the node.
func (n Node) ID() int64 {
	return n.id
}

// Exists is used to check if this handle references an extant node (i.e. if
// the node has been deleted after the handle was obtained).
func (n Node) Exists() bool {
	_, ok := n.graph.nodeData[n.id]
	return ok
}

// Data returns the data attached to the node. This method may error if the
// node has been deleted from the graph after this handle has been obtained.
func (n Node) Data() (interface{}, error) {
	data, ok := n.graph.nodeData[n.id]
	if !ok {
		return nil, &ErrNoSuchNode{id: n.id}
	}

	return data, nil
}

// MustData is a wrapper around Data() which panics on error.
func (n Node) MustData() interface{} {
	data, err := n.Data()
	if err != nil {
		panic(err)
	}
	return data
}

// ReplaceData replaces the data attached to the specified node.
//
// This function may error if the node has been deleted.
func (n Node) ReplaceData(data interface{}) error {
	_, ok := n.graph.nodeData[n.id]
	if !ok {
		return &ErrNoSuchNode{id: n.id}
	}

	n.graph.nodeData[n.id] = data
	return nil
}

// ForeachAncestor will execute the given callback once for each ancestor to
// the given node. An ancestor v of node u is a node such that there exists
// some edge (v,u).  Even if multiple such edges (v,u) exist, the callback will
// only be run once for each ancestor.
//
// This function may error if the node has been deleted from the graph after
// the handle was obtained.
func (n Node) ForeachAncestor(callback func(Node)) error {
	_, ok := n.graph.nodeData[n.id]
	if !ok {
		return &ErrNoSuchNode{id: n.id}
	}

	seen := make(map[int64]bool)

	bySink, ok := n.graph.edgesBySink[n.id]
	if !ok {
		// There were no edges with this node as a sink, so the node
		// has no ancestors.
		return nil
	}

	for _, eid := range bySink {
		sourceid := n.graph.sources[eid]

		// Don't visit the same ancestor twice.
		if _, ok := seen[sourceid]; ok {
			continue
		}
		seen[sourceid] = true

		callback(Node{id: sourceid, graph: n.graph})
	}

	return nil
}

// Ancestors is a utility wrapper around ForeachAncestor() which returns a list
// of all ancestors to the node.
func (n Node) Ancestors() ([]Node, error) {
	ancestors := []Node{}
	err := n.ForeachAncestor(func(m Node) {
		ancestors = append(ancestors, m)
	})
	if err != nil {
		return nil, err
	}
	return ancestors, nil
}

// MustAncestors wraps Ancestors(), but panics on error.
func (n Node) MustAncestors() []Node {
	result, err := n.Ancestors()
	if err != nil {
		panic(err)
	}
	return result
}

// ForeachSuccessor will execute the given callback once for each successor to
// the given node. A successor v of node u is a node such that there exists
// some edge (u, v).  Even if multiple such edges (u, v) exist, the callback
// will only be run once for each successor.
//
// This function may error if the node has been deleted from the graph after
// the handle was obtained.
func (n Node) ForeachSuccessor(callback func(Node)) error {
	_, ok := n.graph.nodeData[n.id]
	if !ok {
		return &ErrNoSuchNode{id: n.id}
	}

	seen := make(map[int64]bool)

	bySource, ok := n.graph.edgesBySource[n.id]
	if !ok {
		// There were no edges with this node as a source , so the node
		// has no successors.
		return nil
	}

	for _, eid := range bySource {
		sinkid := n.graph.sinks[eid]

		// Don't visit the same ancestor twice.
		if _, ok := seen[sinkid]; ok {
			continue
		}
		seen[sinkid] = true

		callback(Node{id: sinkid, graph: n.graph})
	}

	return nil
}

// Successors is a utility wrapper around ForeachSuccessor() which returns a
// list of all successors to the node.
func (n Node) Successors() ([]Node, error) {
	successors := []Node{}
	err := n.ForeachSuccessor(func(m Node) {
		successors = append(successors, m)
	})
	if err != nil {
		return nil, err
	}
	return successors, nil
}

// MustSuccessors is a utility wrapper around Successors() that panics on
// error.
func (n Node) MustSuccessors() []Node {
	result, err := n.Successors()
	if err != nil {
		panic(err)
	}
	return result
}

// ForeachAdjacent runs the given callback once for each node which is either
// an ancestor or a successor to the given node. If the same node is both an
// ancestor and a successor, it will only be visited once.
//
// This function may error if the node has been deleted from the graph after
// the handle was obtained.
func (n Node) ForeachAdjacent(callback func(Node)) error {
	_, ok := n.graph.nodeData[n.id]
	if !ok {
		return &ErrNoSuchNode{id: n.id}
	}

	seen := make(map[int64]bool)

	err := n.ForeachAncestor(func(m Node) {
		if _, ok := seen[m.id]; !ok {
			callback(m)
			seen[m.id] = true
		}
	})

	if err != nil {
		return err
	}

	err = n.ForeachSuccessor(func(m Node) {
		if _, ok := seen[m.id]; !ok {
			callback(m)
			seen[m.id] = true
		}
	})
	if err != nil {
		return err
	}

	return nil
}

// Adjacent is a utility wrapper around ForeachAdjacent() which returns a list
// of all nofes adjacent to the node.
func (n Node) Adjacent() ([]Node, error) {
	adjacent := []Node{}
	err := n.ForeachAdjacent(func(m Node) {
		adjacent = append(adjacent, m)
	})
	if err != nil {
		return nil, err
	}
	return adjacent, nil
}

// MustAdjacent is a utility wrapper around Adjacent() which panics on error.
func (n Node) MustAdjacent() []Node {
	result, err := n.Adjacent()
	if err != nil {
		panic(err)
	}
	return result
}

// ForeachOutEdge runs the given callback once for each edge which has this
// node as its source.
//
// This function may error if the node has been delete from the graph after the
// handle was obtained.
func (n Node) ForeachOutEdge(callback func(Edge)) error {
	if !n.Exists() {
		return &ErrNoSuchNode{id: n.id}
	}

	bySource, ok := n.graph.edgesBySource[n.id]
	if !ok {
		// There are no out-edges from this node.
		return nil
	}

	for _, eid := range bySource {
		callback(Edge{id: eid, graph: n.graph})
	}

	return nil
}

// OutEdges is a utility wrapper around ForeachOutEdge.
func (n Node) OutEdges() ([]Edge, error) {
	es := []Edge{}
	err := n.ForeachOutEdge(func(e Edge) {
		es = append(es, e)
	})
	return es, err
}

// MustOutEdges is a utility wrapper around OutEdges which panics on error.
func (n Node) MustOutEdges() []Edge {
	result, err := n.OutEdges()
	if err != nil {
		panic(err)
	}
	return result
}

// ForeachInEdge runs the given callback once for each edge which has this
// node as its sink.
//
// This function may error if the node has been delete from the graph after the
// handle was obtained.
func (n Node) ForeachInEdge(callback func(Edge)) error {
	if !n.Exists() {
		return &ErrNoSuchNode{id: n.id}
	}

	bySink, ok := n.graph.edgesBySink[n.id]
	if !ok {
		// There are no out-edges from this node.
		return nil
	}

	for _, eid := range bySink {
		callback(Edge{id: eid, graph: n.graph})
	}

	return nil
}

// InEdges is a utility wrapper around ForeachInEdge.
func (n Node) InEdges() ([]Edge, error) {
	es := []Edge{}
	err := n.ForeachInEdge(func(e Edge) {
		es = append(es, e)
	})
	return es, err
}

// MustInEdges is a utility wrapper around InEdges which panics on error.
func (n Node) MustInEdges() []Edge {
	result, err := n.InEdges()
	if err != nil {
		panic(err)
	}
	return result
}

// ForeachEdge runs the given callback for each edge which has this node as
// either a source or a sink. In the case of duplicate edges (e.g. self-edges),
// the callback will still only be called once per edge.
//
// This function may error if the node has been delete from the graph after the
// handle was obtained.
func (n Node) ForeachEdge(callback func(Edge)) error {
	seen := make(map[int64]bool)

	err := n.ForeachOutEdge(func(e Edge) {
		if _, ok := seen[e.id]; !ok {
			seen[e.id] = true
			callback(e)
		}

	})

	if err != nil {
		return err
	}

	err = n.ForeachInEdge(func(e Edge) {
		if _, ok := seen[e.id]; !ok {
			seen[e.id] = true
			callback(e)
		}
	})

	return err
}

// Edges is a utility wrapper around ForeachEdge.
func (n Node) Edges() ([]Edge, error) {
	es := []Edge{}
	err := n.ForeachEdge(func(e Edge) {
		es = append(es, e)
	})
	return es, err
}

// MustEdges is a utility wrapper around Edges which panics on error.
func (n Node) MustEdges() []Edge {
	result, err := n.Edges()
	if err != nil {
		panic(err)
	}
	return result
}

// Delete removes the node from the graph. After calling this function, the
// node handle will become invalid, as will all other handles to this node.
// Any data attached to the node will also be deleted.
//
// Deletion can error if the node does not exist, or if the deletion would
// result in dangling edges.
func (n Node) Delete() error {
	if !n.Exists() {
		return &ErrNoSuchNode{id: n.id}
	}

	adjacent, err := n.Adjacent()
	if err != nil {
		return err
	}

	if len(adjacent) > 0 {
		return &ErrIntegrity{message: fmt.Sprintf("deleting node %d would leave dangling edges to nodes: %v", n.id, adjacent)}
	}

	delete(n.graph.nodeData, n.id)

	// Avoid leaving dangling, empty lists.
	delete(n.graph.edgesBySink, n.id)
	delete(n.graph.edgesBySource, n.id)

	return nil
}

// ForEachBFS implements a breadth-first traversal of the graph, rooted at node n.
// Each time a node is visited, the callback is run on it. The callback may
// return "true" to indicate the search should continue, and "false" to
// indicate that the search should terminate.
//
// This function may error if the node has been deleted since the handle was
// obtained.
func (n Node) ForEachBFS(callback func(Node) bool) error {
	if !n.Exists() {
		return &ErrNoSuchNode{id: n.id}
	}

	// q is used to track the nodes that we have yet to visit.
	q := NewInt64Queue()

	// explored is used to track which nodes we have already visited, so
	// that we can avoid visting them more than once.
	explored := make(map[int64]bool)
	q.Enqueue(n.id)
	explored[n.id] = true

	for q.Len() > 0 {
		// Since the for loop checks that the queue isn't empty, this
		// will always work.
		dq, _ := q.Dequeue()
		m := Node{id: dq, graph: n.graph}

		if !callback(m) {
			return nil
		}

		err := m.ForeachSuccessor(func(w Node) {
			_, ok := explored[w.id]
			if !ok {
				explored[w.id] = true
				q.Enqueue(w.id)
			}
		})

		if err != nil {
			return err
		}
	}

	return nil
}

// BFS is a wrapper around ForEachBFS which simply returns all nodes reachable
// from n in BFS traversal order.
func (n Node) BFS() ([]Node, error) {
	visited := []Node{}

	err := n.ForEachBFS(func(m Node) bool {
		visited = append(visited, m)
		return true
	})

	return visited, err
}

// MustBFS is a utility wrapper around BFS() which panics on error.
func (n Node) MustBFS() []Node {
	result, err := n.BFS()
	if err != nil {
		panic(err)
	}
	return result
}

// ForEachDFS implements a breadth-first traversal of the graph, rooted at node n.
// Each time a node is visited, the callback is run on it. The callback may
// return "true" to indicate the search should continue, and "false" to
// indicate that the search should terminate.
//
// This function may error if the node has been deleted since the handle was
// obtained.
func (n Node) ForEachDFS(callback func(Node) bool) error {
	if !n.Exists() {
		return &ErrNoSuchNode{id: n.id}
	}

	// s is used to track the nodes that we have yet to visit.
	s := NewInt64Stack()
	s.Push(n.id)

	// discovered is used to track nodes we have already discovered to
	// avoid duplicate visists.
	discovered := make(map[int64]bool)

	for s.Len() > 0 {
		// Since the for loop checks that the stack isn't empty, this
		// will always work.
		dq, _ := s.Pop()
		m := Node{id: dq, graph: n.graph}

		if !callback(m) {
			return nil
		}

		_, ok := discovered[m.id]
		if !ok {
			discovered[m.id] = true
			err := m.ForeachSuccessor(func(w Node) {
				_, ok := discovered[w.id]
				if !ok {
					s.Push(w.id)
				}
			})
			if err != nil {
				return err
			}
		}

	}

	return nil
}

// DFS is a wrapper around ForEachDFS which simply returns all nodes reachable
// from n in DFS traversal order.
func (n Node) DFS() ([]Node, error) {
	visited := []Node{}

	err := n.ForEachDFS(func(m Node) bool {
		visited = append(visited, m)
		return true
	})

	return visited, err
}

// MustDFS is a utility wrapper around DFS() which panics on error.
func (n Node) MustDFS() []Node {
	result, err := n.DFS()
	if err != nil {
		panic(err)
	}
	return result
}
