package strategies

import (
	epb "buzzer/proto/ebpf_go_proto"
	"container/heap"
)

// CoverageTrace is used to "score" a program based on its coverage, this is
// for sorting purposes on the heap.
type CoverageTrace struct {
	Program           []*epb.Instruction
	CoverageSignature uint64
	CoverageSize      uint64
	UsageCount        int
}

// PriorityQueueContainer is an alias of an array of traces.
type PriorityQueueContainer []*CoverageTrace

// Len returns how many elements there are in the priority queue.
func (pq PriorityQueueContainer) Len() int { return len(pq) }

// Less is used to give priority on the elements.
func (pq PriorityQueueContainer) Less(i, j int) bool {
	return pq[i].CoverageSize > pq[j].CoverageSize // Higher priority is a larger value
}

// Swap exchanges two elements on the queue.
func (pq PriorityQueueContainer) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
}

// Push Adds one element to the queue.
func (pq *PriorityQueueContainer) Push(x interface{}) {
	item := x.(*CoverageTrace)
	*pq = append(*pq, item)
}

// Pop removes an element from the queue.
func (pq *PriorityQueueContainer) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil // avoid memory leak
	*pq = old[0 : n-1]
	return item
}

// PriorityQueue is a convenient wrap around the container. This struct and
// all the methods below serve the simple purpose of making it easier for
// callers to interact with the priority queue.
type PriorityQueue struct {
	pq *PriorityQueueContainer
}

func (pq *PriorityQueue) Push(ct *CoverageTrace) {
	heap.Push(pq.pq, ct)
}

func (pq *PriorityQueue) Pop() *CoverageTrace {
	if pq.IsEmpty() {
		return nil
	}
	return heap.Pop(pq.pq).(*CoverageTrace)
}

func (pq *PriorityQueue) Len() int {
	return pq.pq.Len()
}

func (pq *PriorityQueue) IsEmpty() bool {
	return pq.Len() == 0
}

// NewPriorityQueue is a factory method to create new pqs.
func NewPriorityQueue() *PriorityQueue {
	return &PriorityQueue{
		pq: &PriorityQueueContainer{},
	}
}
