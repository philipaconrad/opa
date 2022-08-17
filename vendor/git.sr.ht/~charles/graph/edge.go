package graph

// Edge represents a handle to a specific edge in the graph. Edges are
// immutable, and internally contain an edge ID (referencing into the
// underlying data store), and a pointer to the underlying graph.
type Edge struct {
	id    int64
	graph *Graph
}

// ID returns the edge's ID.
func (e Edge) ID() int64 {
	return e.id
}

// Exists is used to check if this handle references an extant edge (i.e. if
// the edge has been deleted after the handle was obtained).
func (e Edge) Exists() bool {
	_, ok := e.graph.edgeData[e.id]
	return ok
}

// Data returns the data associated with the edge.
//
// This function may error if the edge has been removed from the graph after
// the handle has been obtained.
func (e Edge) Data() (interface{}, error) {
	data, ok := e.graph.edgeData[e.id]
	if !ok {
		return nil, &ErrNoSuchEdge{id: e.id}
	}

	return data, nil
}

// MustData is a utility wrapper around Data() which panics on error.
func (e Edge) MustData() interface{} {
	data, err := e.Data()
	if err != nil {
		panic(err)
	}
	return data
}

// ReplaceData replaces the data attached to the specified edge.
//
// This function may error if the edge has been deleted.
func (e Edge) ReplaceData(data interface{}) error {
	_, ok := e.graph.edgeData[e.id]
	if !ok {
		return &ErrNoSuchEdge{id: e.id}
	}

	e.graph.edgeData[e.id] = data
	return nil
}

// Source returns the source node of the edge.
//
// This function may error if the edge has been removed from the graph after
// the handle has been obtained.
func (e Edge) Source() (Node, error) {
	// Note that all edges must always have sources or sinks, so even
	// though the canonical way of checking for existence is via the
	// edgeData table, using sources in this way is also safe.

	source, ok := e.graph.sources[e.id]
	if !ok {
		return Node{}, &ErrNoSuchEdge{id: e.id}
	}

	return Node{id: source, graph: e.graph}, nil
}

// MustSource is a utility wrapper around Source() which panics on error.
func (e Edge) MustSource() Node {
	source, err := e.Source()
	if err != nil {
		panic(err)
	}
	return source
}

// Sink returns the sink node of the edge.
//
// This function may error if the edge has been removed from the graph after
// the handle has been obtained.
func (e Edge) Sink() (Node, error) {
	// Note that all edges must always have sinks or sinks, so even
	// though the canonical way of checking for existence is via the
	// edgeData table, using sinks in this way is also safe.

	sink, ok := e.graph.sinks[e.id]
	if !ok {
		return Node{}, &ErrNoSuchEdge{id: e.id}
	}

	return Node{id: sink, graph: e.graph}, nil
}

// MustSink is a utility wrapper around Sink() which panics on error.
func (e Edge) MustSink() Node {
	sink, err := e.Sink()
	if err != nil {
		panic(err)
	}
	return sink
}

// Delete removes the edge from the graph. After calling this function, the
// edge handle will become invalid, as will all other handles to this edge. Any
// data attached to the edge will also be deleted.
//
// This function can error if the edge does not exist.
func (e Edge) Delete() error {
	if !e.Exists() {
		return &ErrNoSuchEdge{id: e.id}
	}

	// These should only error if the graph data is corrupted.
	source, err := e.Source()
	if err != nil {
		return err
	}
	sink, err := e.Sink()
	if err != nil {
		return err
	}

	delete(e.graph.edgeData, e.id)
	delete(e.graph.sources, e.id)
	delete(e.graph.sinks, e.id)

	e.graph.edgesBySink[sink.id] = RemoveInt64ByValue(e.graph.edgesBySink[sink.id], e.id)
	e.graph.edgesBySource[source.id] = RemoveInt64ByValue(e.graph.edgesBySource[source.id], e.id)

	return nil
}
