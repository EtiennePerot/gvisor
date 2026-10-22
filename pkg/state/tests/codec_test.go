// Copyright 2026 The gVisor Authors.
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

package tests

import (
	"bytes"
	"fmt"
	"math/rand"
	"reflect"
	"testing"

	"gvisor.dev/gvisor/pkg/state/tests/foreign"
)

// graphBuilder builds random object graphs.
type graphBuilder struct {
	seed  int
	r     *rand.Rand
	nodes []*graphNode
	// hasMaps is set if the graph has a map with more than one entry. Its
	// encoding depends on iteration order, as does the order in which
	// objects are found (and so object IDs and the order of types).
	hasMaps bool
}

func (b *graphBuilder) leaf() graphLeaf {
	r := b.r
	l := graphLeaf{}
	if r.Intn(4) == 0 {
		return l // Zero value.
	}
	l.A = int8(r.Intn(256) - 128)
	l.B = r.Uint32() >> uint(r.Intn(32))
	if r.Intn(2) == 0 {
		l.C = string(rune('a' + r.Intn(26)))
	}
	l.D = r.NormFloat64()
	l.E = r.Intn(2) == 0
	l.F = graphName(r.Intn(70000))
	l.G = complex(r.Float32(), -r.Float32())
	for i := range l.H {
		l.H[i] = byte(r.Intn(3) * 100)
	}
	l.I = uintptr(r.Uint64() >> uint(r.Intn(64)))
	return l
}

// ownsLeaf returns true if l is a leaf of the graph outside maps.
func (b *graphBuilder) ownsLeaf(l *graphLeaf) bool {
	for _, nd := range b.nodes {
		if l == &nd.Leaf || l == nd.LeafPtr || l == &nd.Arr[0] || l == &nd.Arr[1] {
			return true
		}
		for i := range nd.Leaves {
			if l == &nd.Leaves[i] {
				return true
			}
		}
	}
	return false
}

func (b *graphBuilder) node() *graphNode {
	return b.nodes[b.r.Intn(len(b.nodes))]
}

// build builds a graph of n nodes and returns its root.
func (b *graphBuilder) build(n int) *graphNode {
	r := b.r
	b.nodes = make([]*graphNode, n)
	for i := range b.nodes {
		nd := &graphNode{Leaf: b.leaf(), Val: int32(r.Intn(1000) - 500), Box: r.Int63()}
		for j := range nd.Ints {
			if r.Intn(2) == 0 {
				nd.Ints[j] = r.Int63() - r.Int63()
			}
		}
		for j := range nd.Arr {
			nd.Arr[j] = b.leaf()
		}
		if r.Intn(2) == 0 {
			nd.Leaves = make([]graphLeaf, r.Intn(4), 1+r.Intn(4)+3)
			for j := range nd.Leaves {
				nd.Leaves[j] = b.leaf()
			}
		}
		switch r.Intn(3) {
		case 0:
			nd.Bytes = []byte{}
		case 1:
			nd.Bytes = make([]byte, r.Intn(20))
			r.Read(nd.Bytes)
		}
		if r.Intn(3) == 0 {
			nd.Names = graphNames{graphName(r.Intn(10)), 0, graphName(r.Intn(10))}
		}
		if r.Intn(2) == 0 {
			nd.FB = make(foreign.Bytes, r.Intn(5), 5)
			r.Read(nd.FB)
		}
		if r.Intn(2) == 0 {
			r.Read(nd.FA[:])
		}
		if r.Intn(2) == 0 {
			nd.FI = foreign.Ints{r.Int31(), 0}
		}
		b.nodes[i] = nd
	}
	for i, nd := range b.nodes {
		if r.Intn(2) == 0 {
			nd.Next = b.node()
		}
		if j := i + 1 + r.Intn(len(b.nodes)); j < len(b.nodes) {
			// Waits must not form cycles.
			nd.W = b.nodes[j]
		}
		switch r.Intn(5) {
		case 0:
			nd.LeafPtr = &b.node().Leaf
		case 1:
			o := b.node()
			nd.LeafPtr = &o.Arr[r.Intn(len(o.Arr))]
		case 2:
			if o := b.node(); len(o.Leaves) > 0 {
				nd.LeafPtr = &o.Leaves[r.Intn(len(o.Leaves))]
			}
		case 3:
			nd.LeafPtr = &graphLeaf{F: 7}
		}
		switch r.Intn(3) {
		case 0:
			o := b.node()
			nd.IntPtr = &o.Ints[r.Intn(len(o.Ints))]
		case 1:
			v := r.Int63()
			nd.IntPtr = &v
		}
		if r.Intn(4) == 0 {
			nd.ArrPtr = &b.node().Ints
		}
		if k := r.Intn(4); k > 0 {
			nd.Kids = make([]*graphNode, k)
			for j := range nd.Kids {
				if r.Intn(4) != 0 {
					nd.Kids[j] = b.node()
				}
			}
			if r.Intn(3) == 0 {
				nd.Kids = nd.Kids[r.Intn(k):]
			}
		}
		if o := b.node(); o != nd && len(o.Leaves) > 1 && r.Intn(3) == 0 {
			// Share another node's slice. Save does not support slices of
			// a backing array at different offsets, and zeroes the elements
			// of a backing array beyond the length of a slice.
			nd.Leaves = o.Leaves
		}
		if r.Intn(5) == 0 {
			// Slice an array field of another node.
			nd.Leaves = b.node().Arr[:]
		}
		if o := b.node(); o != nd && len(o.Bytes) > 2 && r.Intn(3) == 0 {
			nd.Bytes = o.Bytes
		}
		switch r.Intn(6) {
		case 0:
			nd.Any = b.node()
		case 1:
			nd.Any = &b.node().Leaf
		case 2:
			nd.Any = int(r.Intn(100))
		case 3:
			nd.Any = (*graphNode)(nil)
		}
		switch r.Intn(3) {
		case 0:
			nd.Iface = b.node()
		case 1:
			nd.Iface = &b.node().Arr[1]
		}
		if k := r.Intn(4); k > 0 {
			if b.seed%2 == 0 {
				k = 1 // Keep encodings deterministic.
			}
			nd.M = make(map[int32]*graphNode)
			for j := 0; j < k; j++ {
				nd.M[int32(r.Intn(10))] = b.node()
			}
			if len(nd.M) > 1 {
				b.hasMaps = true
			}
		}
		if r.Intn(4) == 0 {
			nd.MS = map[graphName]graphLeaf{graphName(r.Intn(5)): b.leaf()}
		}
		for j := range nd.Links {
			if r.Intn(2) == 0 {
				v := r.Int63()
				nd.Links[j].I = &v
			}
			if r.Intn(2) == 0 {
				nd.Links[j].N = b.node()
			}
		}
		if r.Intn(2) == 0 {
			nd.LinkS = make([]graphLink, 1+r.Intn(3))
			for j := range nd.LinkS {
				v := r.Int63()
				nd.LinkS[j] = graphLink{N: b.node(), I: &v}
			}
		}
		// Refer to links in other nodes, which may be found (and their
		// pointers followed) before the containing node or slice.
		switch r.Intn(3) {
		case 0:
			nd.LinkPtr = &b.node().Links[r.Intn(2)]
		case 1:
			if o := b.node(); len(o.LinkS) > 0 {
				nd.LinkPtr = &o.LinkS[r.Intn(len(o.LinkS))]
			}
		}
	}
	return b.nodes[0]
}

// diff describes the first difference between a and b.
func diff(a, b []byte) string {
	i := 0
	for i < len(a) && i < len(b) && a[i] == b[i] {
		i++
	}
	window := func(x []byte) []byte {
		return x[max(0, i-16):min(len(x), i+16)]
	}
	return fmt.Sprintf("lengths %d and %d, first difference at %d: %v vs %v", len(a), len(b), i, window(a), window(b))
}

// TestCodecRandomGraphs checks the generated codecs against the
// reflection-based implementation on random object graphs: each decoder must
// reproduce the graph, including pointer aliasing (checked by comparing the
// reflection-based encodings of the original and loaded graphs, when they do
// not depend on map iteration order), and each struct must be saved once.
func TestCodecRandomGraphs(t *testing.T) {
	seeds := 500
	if testing.Short() {
		seeds = 50
	}
	for seed := 0; seed < seeds; seed++ {
		b := graphBuilder{seed: seed, r: rand.New(rand.NewSource(int64(seed)))}
		root := b.build(1 + seed%17)
		var encoded [2][]byte
		for i, codecs := range []bool{false, true} {
			clear(graphSaves)
			data, _, err := save(root, codecs)
			if err != nil {
				t.Fatalf("seed %d: save (codecs=%t) failed: %v", seed, codecs, err)
			}
			for p, n := range graphSaves {
				if l, ok := p.(*graphLeaf); ok && !b.ownsLeaf(l) {
					// Map values are saved from copies, whose
					// addresses may be reused.
					continue
				}
				if n != 1 {
					t.Fatalf("seed %d: save (codecs=%t) saved %T %p %d times", seed, codecs, p, p, n)
				}
			}
			encoded[i] = data
		}
		reflectData, codecData := encoded[0], encoded[1]
		for _, enc := range []struct {
			name string
			data []byte
		}{{"reflect", reflectData}, {"codec", codecData}} {
			for _, codecs := range []bool{false, true} {
				if enc.name == "codec" && !codecs {
					// The typed format requires codecs.
					continue
				}
				loaded, _, err := load(reflect.TypeOf(root), enc.data, codecs)
				if err != nil {
					t.Fatalf("seed %d: load (codecs=%t) of %s encoding failed: %v", seed, codecs, enc.name, err)
				}
				got := loaded.(*graphNode)
				// Loaded counts afterLoad calls; it is not saved.
				for _, nd := range b.nodes {
					nd.Loaded = 1
				}
				if !reflect.DeepEqual(root, got) {
					t.Fatalf("seed %d: load (codecs=%t) of %s encoding differs", seed, codecs, enc.name)
				}
				for _, nd := range b.nodes {
					nd.Loaded = 0
				}
				// Saving the loaded graph must give the same encoding,
				// which checks that aliasing was preserved.
				again, _, err := save(got, false)
				if err != nil {
					t.Fatalf("seed %d: saving loaded graph failed: %v", seed, err)
				}
				if !b.hasMaps && !bytes.Equal(again, reflectData) {
					t.Fatalf("seed %d: load (codecs=%t) of %s encoding: re-encoding differs (maps %t): %s", seed, codecs, enc.name, b.hasMaps, diff(reflectData, again))
				}
			}
		}
	}
}

// TestCodecAbsorbedReferrer checks an object whose only referrer is merged
// into a containing object after referring to it.
func TestCodecAbsorbedReferrer(t *testing.T) {
	v := int64(42)
	arr := &[2]graphLink{{}, {I: &v}}
	// Saving root finds arr[1] first, and follows its pointer to v, before
	// finding arr through root.Next.Next.
	root := &graphNode{LinkPtr: &arr[1], Next: &graphNode{Next: &graphNode{LinkS: arr[:]}}}
	data, _, err := save(root, true)
	if err != nil {
		t.Fatalf("save failed: %v", err)
	}
	loaded, _, err := load(reflect.TypeOf(root), data, true)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	got := loaded.(*graphNode)
	if got.LinkPtr == nil || got.LinkPtr.I == nil || *got.LinkPtr.I != 42 {
		t.Fatalf("got LinkPtr %+v, want a link to 42", got.LinkPtr)
	}
	if got.LinkPtr != &got.Next.Next.LinkS[1] {
		t.Errorf("LinkPtr does not point into Next.Next.LinkS")
	}
}

// TestCodecStandalone checks a backing array found through a pointer to an
// element, whose slice is only reachable from that element, so that the
// encoder writes it without a preceding reference providing its decoder.
func TestCodecStandalone(t *testing.T) {
	o := &graphNode{}
	o.LinkS = []graphLink{{N: o}}
	root := &graphNode{LinkPtr: &o.LinkS[0]}
	data, _, err := save(root, true)
	if err != nil {
		t.Fatalf("save failed: %v", err)
	}
	loaded, _, err := load(reflect.TypeOf(root), data, true)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	got := loaded.(*graphNode)
	if got.LinkPtr == nil || got.LinkPtr.N == nil {
		t.Fatalf("got LinkPtr %+v, want a link to a node", got.LinkPtr)
	}
	if n := got.LinkPtr.N; len(n.LinkS) != 1 || &n.LinkS[0] != got.LinkPtr || n.LinkS[0].N != n {
		t.Errorf("got node %+v, want LinkS[0] at LinkPtr referring to the node", n)
	}
}

// TestCodecNestedMaps checks maps whose values are maps.
func TestCodecNestedMaps(t *testing.T) {
	root := &nestedMaps{M: map[int]map[int32]struct{}{0: {1: {}, 5: {}}, 15: {7: {}}, 3: {}}}
	data, _, err := save(root, true)
	if err != nil {
		t.Fatalf("save failed: %v", err)
	}
	loaded, _, err := load(reflect.TypeOf(root), data, true)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if got := loaded.(*nestedMaps); !reflect.DeepEqual(got, root) {
		t.Errorf("got %v, want %v", got.M, root.M)
	}
}
