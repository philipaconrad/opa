package graph

import (
	"fmt"
)

//// ErrNoSuchNode ////////////////////////////////////////////////////////////

// Declare conformance with error.
var _ error = (*ErrNoSuchNode)(nil)

// ErrNoSuchNode is thrown when an operation is requested on a node which does
// not exist.
type ErrNoSuchNode struct {
	id int64
}

// Error implements the error interface
func (e *ErrNoSuchNode) Error() string {
	return fmt.Sprintf("no such node: %d", e.id)
}

//// ErrNoSuchEdge ////////////////////////////////////////////////////////////

// Declare conformance with error.
var _ error = (*ErrNoSuchEdge)(nil)

// ErrNoSuchEdge is thrown when an operation is requested on an edge which does
// not exist.
type ErrNoSuchEdge struct {
	id int64
}

// Error implements the error interface
func (e *ErrNoSuchEdge) Error() string {
	return fmt.Sprintf("no such edge: %d", e.id)
}

//// ErrIntegrity /////////////////////////////////////////////////////////////

// Declare conformance with error.
var _ error = (*ErrIntegrity)(nil)

// ErrIntegrity is thrown when the requested operation could result in data
// corruption, for example deleting a node that would leave dangling edges.
type ErrIntegrity struct {
	message string
}

// Error implements the error interface
func (e *ErrIntegrity) Error() string {
	return fmt.Sprintf("integrity error: %s", e.message)
}
