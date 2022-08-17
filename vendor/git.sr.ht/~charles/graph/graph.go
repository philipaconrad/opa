package graph

// Graph implements a directed graph.
type Graph struct {

	// nodeData stores the data associated with each node, keyed by node
	// ID.
	nodeData map[int64]interface{}

	// edgeData stores the data associated with each edge, keyed by node
	// ID.
	edgeData map[int64]interface{}

	// sources is keyed by edge ID, and stores which node is the source for
	// the specified edge.
	sources map[int64]int64

	// sinks is keyed by edge ID, and stores which node is the sink for
	// the specified edge.
	sinks map[int64]int64

	// edgeBySink is keyed by node ID, with the value being the list of all
	// edges for which the key node is the sink.
	edgesBySink map[int64][]int64

	// edgeBySource is keyed by node ID, with the value being the list of
	// all edges for which the key node is the source.
	edgesBySource map[int64][]int64

	// nextID is used to store the next unused ID in the graph. This is
	// shared between nodes and edges to reduce the odds of an error.  It
	// is also initialized to 1 so that initialized int64 values won't be
	// in the graph.
	nextID int64
}

// NewGraph instantiates a new empty Graph object.
func NewGraph() *Graph {
	return &Graph{
		nodeData:      map[int64]interface{}{},
		edgeData:      map[int64]interface{}{},
		sources:       map[int64]int64{},
		sinks:         map[int64]int64{},
		edgesBySink:   map[int64][]int64{},
		edgesBySource: map[int64][]int64{},
		nextID:        1,
	}
}

// getNextID returns the next available ID.
func (g *Graph) getNextID() int64 {
	temp := g.nextID

	g.nextID++
	return temp
}

// EdgeByID retrieves the given edge by its ID, and a flag indicating if
// the edge exists or not. If the flag is false, the returned edge handle
// will not be valid.
func (g *Graph) EdgeByID(id int64) (Edge, bool) {
	e := Edge{id: id, graph: g}
	if !e.Exists() {
		return Edge{id: 0, graph: nil}, false
	}
	return e, true
}

// NodeByID retrieves the given node by its ID, and a flag indicating if
// the node exists or not. If the flag is false, the returned node handle
// will not be valid.
func (g *Graph) NodeByID(id int64) (Node, bool) {
	n := Node{id: id, graph: g}
	if !n.Exists() {
		return Node{id: 0, graph: nil}, false
	}
	return n, true
}

// EdgesBetween returns a list of all edges which have the specified source and
// sink. This function is directed (edges from the sink to the source are not
// included).
//
// This function may error if the source or sink do not exist.
func (g *Graph) EdgesBetween(source, sink Node) ([]Edge, error) {

	// Validate the existence of the source and sink.
	if !sink.Exists() {
		return nil, &ErrNoSuchNode{id: sink.id}
	}
	if !source.Exists() {
		return nil, &ErrNoSuchNode{id: source.id}
	}

	result := []Edge{}

	bySource, ok := g.edgesBySource[source.id]
	if !ok {
		// The source is not the source of any edge
		return result, nil
	}

	for _, eid := range bySource {
		esink := g.sinks[eid]
		if esink == sink.id {
			result = append(result, Edge{id: eid, graph: g})
		}
	}

	return result, nil
}

// MustEdgesBetween is a utility wrapper around EdgesBetween() that panics on
// error.
func (g *Graph) MustEdgesBetween(source, sink Node) []Edge {
	result, err := g.EdgesBetween(source, sink)
	if err != nil {
		panic(err)
	}
	return result
}

// NewEdgeWithData creates a new edge between the specified source and sink
// nodes, with the specified data.
//
// This function may error if the source or sink do not exist, or if the
// SingleEdge tunable is asserted and an edge already exists between the given
// pair of nodes. In the latter case, the error will be of type ErrTunable.
func (g *Graph) NewEdgeWithData(source, sink Node, data interface{}) (Edge, error) {

	// Validate the existence of the source and sink.
	if !sink.Exists() {
		return Edge{}, &ErrNoSuchNode{id: sink.id}
	}
	if !source.Exists() {
		return Edge{}, &ErrNoSuchNode{id: source.id}
	}

	// Everything is good to go, instantiate the edge...
	eid := g.getNextID()
	g.edgeData[eid] = data
	g.sources[eid] = source.id
	g.sinks[eid] = sink.id

	_, ok := g.edgesBySink[sink.id]
	if !ok {
		g.edgesBySink[sink.id] = make([]int64, 0)
	}
	g.edgesBySink[sink.id] = append(g.edgesBySink[sink.id], eid)

	_, ok = g.edgesBySource[source.id]
	if !ok {
		g.edgesBySource[source.id] = make([]int64, 0)
	}
	g.edgesBySource[source.id] = append(g.edgesBySource[source.id], eid)

	return Edge{id: eid, graph: g}, nil
}

// MustNewEdgeWithData is a utility wrapper around NewEdgeWithData() that
// panics on error.
func (g *Graph) MustNewEdgeWithData(source, sink Node, data interface{}) Edge {
	e, err := g.NewEdgeWithData(source, sink, data)
	if err != nil {
		panic(err)
	}
	return e
}

// NewNodeWithData creates a new node in the graph with the specified data,
// returning the node handle.
func (g *Graph) NewNodeWithData(data interface{}) Node {
	id := g.getNextID()
	g.nodeData[id] = data
	return Node{id: id, graph: g}
}

// ForeachNode runs the given callback on each node in the graph in an
// arbitrary order.
//
// The callback may return true to proceed, or false to stop iteration
// immediately.
func (g *Graph) ForeachNode(callback func(Node) bool) {
	for k := range g.nodeData {
		keepgoing := callback(Node{id: k, graph: g})
		if !keepgoing {
			return
		}
	}
}

// Nodes is a wrapper around ForEachNode which collects all nodes in the graph
// into a single slice, in an arbitrary order.
func (g *Graph) Nodes() []Node {
	nodes := []Node{}
	g.ForeachNode(func(n Node) bool {
		nodes = append(nodes, n)
		return true
	})
	return nodes
}

// ForeachEdge runs the given callback on each edge in the graph in an
// arbitrary order.
//
// The callback may return true to proceed, or false to stop iteration
// immediately.
func (g *Graph) ForeachEdge(callback func(Edge) bool) {
	for k := range g.edgeData {
		keepgoing := callback(Edge{id: k, graph: g})
		if !keepgoing {
			return
		}
	}
}

// Edges is a wrapper around ForEachEdge which collects all edges in the graph
// into a single slice, in an arbitrary order.
func (g *Graph) Edges() []Edge {
	edges := []Edge{}
	g.ForeachEdge(func(e Edge) bool {
		edges = append(edges, e)
		return true
	})
	return edges
}
