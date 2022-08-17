package graph

// CompareNodeLists returns true if and only if every node in l1 appears in l2
// at least once, and every node in l2 appears in l1 at least once.
func CompareNodeLists(l1, l2 []Node) bool {
	l1int := []int64{}
	l2int := []int64{}

	for _, v := range l1 {
		l1int = append(l1int, v.id)
	}

	for _, v := range l2 {
		l2int = append(l2int, v.id)
	}

	return CompareInt64Lists(l1int, l2int)
}

// CompareEdgeLists returns true if and only if every edge in l1 appears in l2
// at least once, and every edge in l2 appears in l1 at least once.
func CompareEdgeLists(l1, l2 []Edge) bool {
	l1int := []int64{}
	l2int := []int64{}

	for _, v := range l1 {
		l1int = append(l1int, v.id)
	}

	for _, v := range l2 {
		l2int = append(l2int, v.id)
	}

	return CompareInt64Lists(l1int, l2int)

}

// CompareInt64Lists implements the under-the-hood logic for CompareNodeLists()
// and CompareEdgeLists().
func CompareInt64Lists(l1, l2 []int64) bool {
	l1map := make(map[int64]bool)
	l2map := make(map[int64]bool)

	for _, i := range l1 {
		l1map[i] = true
	}

	for _, i := range l2 {
		l2map[i] = true
	}

	for k := range l1map {
		_, ok := l2map[k]
		if !ok {
			return false
		}
	}

	for k := range l2map {
		_, ok := l1map[k]
		if !ok {
			return false
		}
	}

	return true
}

// RemoveInt64ByValue removes all instances of the specified value from the
// given list in-place.
func RemoveInt64ByValue(l []int64, val int64) []int64 {
	cleared := []int64{}
	for _, v := range l {
		if v != val {
			cleared = append(cleared, v)
		}
	}
	return cleared
}

// Int64Queue implements a simple FIFO queue for int64 data.
type Int64Queue struct {
	elements []int64
}

// NewInt64Queue instantiates a new, empty queue.
func NewInt64Queue() *Int64Queue {
	return &Int64Queue{elements: []int64{}}
}

// Enqueue inserts a new item into the queue.
func (q *Int64Queue) Enqueue(v int64) {
	q.elements = append(q.elements, v)
}

// Dequeue removes the head of the queue and returns it, or else returns (-1,
// false) if the queue is empty.
func (q *Int64Queue) Dequeue() (int64, bool) {
	if len(q.elements) < 1 {
		return -1, false
	}
	head := q.elements[0]
	q.elements = q.elements[1:]
	return head, true
}

// Peek returns the head of the queue without removing it, or returns (-1,
// false) if the queue is empty.
func (q *Int64Queue) Peek() (int64, bool) {
	if len(q.elements) < 1 {
		return -1, false
	}
	return q.elements[0], true
}

// Len returns the number of elements in the queue.
func (q *Int64Queue) Len() int {
	return len(q.elements)
}

// CheckInt64PartialOrdering returns true if and only if there exists no
// pair of indices (i,j) in l such that l[i]=u and l[j]=v and i>j. In other
// words, no instance of v is allowed to occur before any instance u.
//
// If u and v do not each occur at least once in l, this function returns
// false.
func CheckInt64PartialOrdering(l []int64, u, v int64) bool {
	firstu := -1
	firstv := -1

	for i, val := range l {
		if (val == u) && (firstu == -1) {
			firstu = i
		}

		if (val == v) && (firstv == -1) {
			firstv = i
		}
	}

	if (firstu == -1) || (firstv == -1) {
		return false
	}

	return firstv > firstu
}

// Int64Stack implements a simple LIFO stack for int64 data.
type Int64Stack struct {
	elements []int64
}

// NewInt64Stack instantiates a new, empty stack.
func NewInt64Stack() *Int64Stack {
	return &Int64Stack{elements: []int64{}}
}

// Push insert an item into the stack.
func (s *Int64Stack) Push(v int64) {
	s.elements = append(s.elements, v)
}

// Pop removes and returns the top element of the stack, or (-1, false) if the
// stack is empty.
func (s *Int64Stack) Pop() (int64, bool) {
	if len(s.elements) < 1 {
		return -1, false
	}
	head := s.elements[len(s.elements)-1]
	s.elements = s.elements[:len(s.elements)-1]
	return head, true
}

// Peek returns the top of the stack without removing it, or returns (-1,
// false) if the stack is empty.
func (s *Int64Stack) Peek() (int64, bool) {
	if len(s.elements) < 1 {
		return -1, false
	}
	return s.elements[len(s.elements)-1], true
}

// Len returns the number of elements in the stack.
func (s *Int64Stack) Len() int {
	return len(s.elements)
}
