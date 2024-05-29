package coveragebased

import (
	epb "buzzer/proto/ebpf_go_proto"
	"container/heap"
)

type CoverageTrace struct {
	Program           []*epb.Instruction
	CoverageSignature uint64
	CoverageSize      uint64
	UsageCount        int
}

type PriorityQueueContainer []*CoverageTrace

func (pq PriorityQueueContainer) Len() int { return len(pq) }

func (pq PriorityQueueContainer) Less(i, j int) bool {
	return pq[i].CoverageSize > pq[j].CoverageSize // Higher priority is a larger value
}

func (pq PriorityQueueContainer) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
}

func (pq *PriorityQueueContainer) Push(x interface{}) {
	item := x.(*CoverageTrace)
	*pq = append(*pq, item)
}

func (pq *PriorityQueueContainer) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil // avoid memory leak
	*pq = old[0 : n-1]
	return item
}

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

func NewPriorityQueue() *PriorityQueue {
	return &PriorityQueue{
		pq: &PriorityQueueContainer{},
	}
}
