package strategies

import (
	"testing"
)

func TestHeap(t *testing.T) {
	t.Run("Test heap order", func(t *testing.T) {
		item1 := &CoverageTrace{
			Program:           nil,
			CoverageSignature: 0xcafe,
			CoverageSize:      1,
		}

		item2 := &CoverageTrace{
			Program:           nil,
			CoverageSignature: 0xcafd,
			CoverageSize:      0,
		}
		item3 := &CoverageTrace{
			Program:           nil,
			CoverageSignature: 0xbaca,
			CoverageSize:      1337,
		}

		pq := NewPriorityQueue()
		pq.Push(item1)
		pq.Push(item2)
		pq.Push(item3)
		length := pq.Len()
		if length != 3 {
			t.Fatalf("pq.Len() = %d, want 3")
		}
		if pq.IsEmpty() {
			t.Fatalf("pq.IsEmpty() = true, want false")
		}
		e := pq.Pop()
		if e != item3 {
			t.Fatalf("pq.Pop() = %v, want %v", e, item3)
		}
		e = pq.Pop()
		if e != item1 {
			t.Fatalf("pq.Pop() = %v, want %v", e, item1)
		}
		e = pq.Pop()
		if e != item2 {
			t.Fatalf("pq.Pop() = %v, want %v", e, item2)
		}
		length = pq.Len()
		if length != 0 {
			t.Fatalf("pq.Len() = %d, want 0")
		}
		if !pq.IsEmpty() {
			t.Fatalf("pq.IsEmpty() = false, want true")
		}
	})
}
