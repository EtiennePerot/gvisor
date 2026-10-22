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

package state

import (
	"context"
	"reflect"
	"sync/atomic"
)

// Codec is implemented by structs for which go_stateify generated typed
// encoding and decoding methods. Save and Load use these methods instead of
// StateSave and StateLoad, which remain the reference implementation: both
// produce and consume the same wire format.
//
// StateEncode must encode each field listed by StateFields, in order, using
// the Encode* functions of this package. StateDecode must decode them in the
// same order using the Decode* functions.
//
// Types implementing Codec must also implement Type and SaverLoader.
type Codec interface {
	// StateEncode encodes the fields of the object.
	StateEncode(*Encoder)

	// StateDecode decodes the fields of the object.
	StateDecode(context.Context, *Decoder)

	// StateTypeIndex returns per-type storage used by the state package to
	// look up type information without reflection.
	StateTypeIndex() *TypeIndex
}

// TypeIndex is per-type storage for the state package. go_stateify generates
// one for each struct type implementing Codec.
type TypeIndex struct {
	// index is a unique index assigned on first use, or zero.
	index atomic.Uint32
}

// typeIndexCount is the number of assigned type indices.
var typeIndexCount atomic.Uint32

// get returns the index, assigning one if needed.
func (ti *TypeIndex) get() uint32 {
	if index := ti.index.Load(); index != 0 {
		return index
	}
	// Indices are assigned lazily rather than by Register: this would
	// require a Codec type assertion, and the construction of its itab, for
	// every registered type during initialization.
	index := typeIndexCount.Add(1)
	if !ti.index.CompareAndSwap(0, index) {
		return ti.index.Load()
	}
	return index
}

// Mode describes how a value is encoded.
type Mode uint8

const (
	// ModeDefault encodes struct fields and top-level objects: primitive
	// zero values (including nil pointers, slices, maps and interfaces) are
	// encoded as Nil.
	ModeDefault Mode = iota

	// ModeValue encodes array, slice and map elements, and values held in
	// interfaces: values are always encoded in full.
	ModeValue

	// ModeValueUntagged is ModeValue for array and map elements after the
	// first one, which are encoded without their tag.
	ModeValueUntagged
)

// tagged returns true if values encoded with mode m include their tag.
func (m Mode) tagged() bool {
	return m != ModeValueUntagged
}

// strategy returns the encodeStrategy corresponding to m.
func (m Mode) strategy() encodeStrategy {
	if m == ModeDefault {
		return encodeDefault
	}
	return encodeAsValue
}

// elemMode returns the mode of the i-th element of an array or map.
func elemMode(i int) Mode {
	if i == 0 {
		return ModeValue
	}
	return ModeValueUntagged
}

// Unsigned is the set of unsigned integer types.
type Unsigned interface {
	~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr
}

// Signed is the set of signed integer types.
type Signed interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64
}

// typeOf returns the reflect.Type of T. It does not allocate.
func typeOf[T any]() reflect.Type {
	return reflect.TypeFor[T]()
}

// DisableCodecs disables the use of Codec methods by Save and Load, which then
// use StateSave and StateLoad for all types. It returns a function that
// restores the previous setting. It is intended for tests.
func DisableCodecs() func() {
	prev := codecsDisabled
	codecsDisabled = true
	return func() { codecsDisabled = prev }
}

// codecsDisabled is set by DisableCodecs.
var codecsDisabled bool
