// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package rand provides utility methods for the fuzzer
// This package is optimized for fuzzing purposes as it is biased towards 'interesting' integers.
// It also provides utilities for randomly making a choice.
// Last but not least, it contains a wrapper struct with a randomness source associated with it
// to ensure that each fuzzing instance generates unique inputs and has a unique seed.

package rand

import (
	crypto_rand "crypto/rand" // Aliased to avoid conflict
	"encoding/binary"
	"math/rand"
	"sync"
)

// newSeed generates a cryptographically secure 64-bit seed.
// It panics if it can't read from crypto/rand.
func newSeed() int64 {
	var b [8]byte
	if _, err := crypto_rand.Read(b[:]); err != nil {
		panic("cannot seed math/rand: " + err.Error())
	}
	return int64(binary.BigEndian.Uint64(b[:]))
}

// BuzzerRNG wraps a math/rand.Rand generator and its mutex
// to make it thread-safe.
type BuzzerRNG struct {
	r  *rand.Rand
	mu sync.Mutex
}

// New returns a new, securely seeded, thread-safe BuzzerRNG.
func New() *BuzzerRNG {
	return &BuzzerRNG{
		r: rand.New(rand.NewSource(newSeed())),
	}
}

// SharedRNG is the default, package-level singleton generator.
// It is an instance of BuzzerRNG and is safe for concurrent use.
var SharedRNG = New()

// RandInt returns a non-negative pseudo-random int.
func (br *BuzzerRNG) RandInt() int {
	br.mu.Lock()
	defer br.mu.Unlock()
	return br.r.Int()
}

// RandRange returns a non-negative pseudo-random number in [min, max).
func (br *BuzzerRNG) RandRange(min, max uint64) uint64 {
	br.mu.Lock()
	defer br.mu.Unlock()
	return uint64(br.r.Intn(int(max-min+1))) + min
}

// RandBytes returns a byte slice of the given size populated with pseudo-random
// data.
func (br *BuzzerRNG) RandBytes(size int) []byte {
	b := make([]byte, size)
	br.mu.Lock()
	defer br.mu.Unlock()
	if _, err := br.r.Read(b); err != nil {
		// This should never fail
		panic(err)
	}
	return b
}

// RandString returns a string of the given size populated with pseudo-random
// data.
func (br *BuzzerRNG) RandString(size int) string {
	return string(br.RandBytes(size))
}

// RandBool returns a random boolean.
func (br *BuzzerRNG) RandBool() bool {
	br.mu.Lock()
	defer br.mu.Unlock()
	return br.r.Intn(2) == 1
}

// OneOf returns a random element from the given slice.
// It panics if the slice is empty.
func OneOf[T any](choices []T) T {
	if len(choices) == 0 {
		panic("OneOf called with empty slice")
	}
	// Get a random index from the thread-safe SharedRNG
	idx := SharedRNG.RandRange(0, uint64(len(choices)))
	return choices[idx]
}
