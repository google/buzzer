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
	"math/rand"
	"time"
)

var (
	// Some potentially interesting integers - These represent maximum and minimum
	// values for various integer sizes and values that tend to lead to overflow issues
	specialInts = []uint64{
		0, 1, 31, 32, 63, 64, 127, 128,
		129, 255, 256, 257, 511, 512,
		1023, 1024, 1025, 2047, 2048, 4095, 4096,
		(1 << 15) - 1, (1 << 15), (1 << 15) + 1,
		(1 << 16) - 1, (1 << 16), (1 << 16) + 1,
		(1 << 31) - 1, (1 << 31), (1 << 31) + 1,
		(1 << 32) - 1, (1 << 32), (1 << 32) + 1,
		(1 << 63) - 1, (1 << 63), (1 << 63) + 1,
		(1 << 64) - 1,
	}
)

// NumGen provides helper methods for generating random integers. Each instance has its own seed
// to prevent concurrent VMs from generating the same inputs
type NumGen struct {
	r *rand.Rand
}

// NewRand generates a new random number generator
func NewRand(randSource rand.Source) *NumGen {
	return &NumGen{
		r: rand.New(randSource),
	}
}

var SharedRNG = NewRand(rand.NewSource(time.Now().Unix()))

// RandRange returns a random 64-bit integer in the range of begin..end
func (g *NumGen) RandRange(begin, end uint64) uint64 {
	return begin + uint64(g.r.Intn(int(end-begin+1)))
}

// OneOf returns true 1 out of n times
func (g *NumGen) OneOf(n int) bool {
	return g.r.Intn(n) == 0
}

// NOutOf returns true n out of outOf times.
func (g *NumGen) NOutOf(n, outOf int) bool {
	if n <= 0 || n >= outOf {
		panic("bad probability")
	}
	v := g.r.Intn(outOf)
	return v < n
}

// RandInt is the preferred method for generating a random integer. It is biased towards
// 'special' numbers such as 256, 4096, 1 << 31, 1 << 63 etc.
func (g *NumGen) RandInt() uint64 {
	v := uint64(g.r.Int63())

	// All of these proababilities are subject to tuning and can be changed at any time for experiments
	switch {
	case g.NOutOf(3, 10):
		v = specialInts[g.r.Intn(len(specialInts))]
	case g.NOutOf(1, 10):
		v %= 256
	case g.NOutOf(1, 10):
		v %= 64 << 10
	case g.NOutOf(1, 10):
		v %= 1 << 31
	case g.NOutOf(1, 10):
		v = uint64(-int64(v))
	}
	return v
}
