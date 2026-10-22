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
	"context"

	"gvisor.dev/gvisor/pkg/state/tests/foreign"
)

// The types below are used to compare the generated codecs with the
// reflection-based implementation on random object graphs.

type graphName uint16

type graphNames []graphName

// graphIface is implemented by *graphNode and *graphLeaf.
type graphIface interface {
	graph()
}

// +stateify savable
type graphLeaf struct {
	A int8
	B uint32
	C string
	D float64
	E bool
	F graphName
	G complex64
	H [3]byte
	I uintptr
}

func (*graphLeaf) graph() {}

// graphSaves counts calls to beforeSave by address, to check that the state
// package saves each struct once.
var graphSaves = make(map[any]int)

func (l *graphLeaf) beforeSave() {
	graphSaves[l]++
}

// +stateify savable
type graphNode struct {
	Leaf    graphLeaf
	Next    *graphNode
	LeafPtr *graphLeaf
	IntPtr  *int64
	ArrPtr  *[4]int64
	Ints    [4]int64
	Kids    []*graphNode
	Leaves  []graphLeaf
	Bytes   []byte
	Any     any
	Iface   graphIface
	M       map[int32]*graphNode
	MS      map[graphName]graphLeaf
	Arr     [2]graphLeaf
	Names   graphNames
	Val     int32      `state:".(int64)"`
	Box     int64      `state:".(*int64)"`
	W       *graphNode `state:"wait"`
	FB      foreign.Bytes
	FA      foreign.Array
	FE      foreign.Empty
	FI      foreign.Ints
	AE      struct{}
	Links   [2]graphLink
	LinkS   []graphLink
	LinkPtr *graphLink
	Loaded  int `state:"nosave"`
}

// graphLink is a struct with pointers, referred to from outside the object
// containing it.
//
// +stateify savable
type graphLink struct {
	N *graphNode
	I *int64
}

func (*graphNode) graph() {}

func (n *graphNode) saveVal() int64 {
	return int64(n.Val) * 3
}

func (n *graphNode) loadVal(_ context.Context, v int64) {
	n.Val = int32(v / 3)
}

// saveBox returns a new object, which must be saved once.
func (n *graphNode) saveBox() *int64 {
	v := n.Box
	return &v
}

func (n *graphNode) loadBox(_ context.Context, v *int64) {
	n.Box = *v
}

func (n *graphNode) beforeSave() {
	graphSaves[n]++
}

func (n *graphNode) afterLoad(context.Context) {
	n.Loaded++
}

// nestedMaps has a map of maps, like netlink's port.Manager.
//
// +stateify savable
type nestedMaps struct {
	M map[int]map[int32]struct{}
}
