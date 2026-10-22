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
	"hash/fnv"
	"reflect"
	"sort"
	"sync"
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

// The typed format.
//
// Save uses the typed format when codecs are enabled. It is not compatible
// with the format of StateSave, and has no tags or type headers: values are
// encoded as their static types dictate.
//
//   - The stream header has typedFlag set, and is followed by schemaHash: the
//     types of the encoder and decoder must match exactly.
//   - Objects follow, each preceded by its ID (as a tagged Uint), possibly
//     preceded by type definitions (as by StateSave), and followed by its
//     kind: objectTyped, objectLegacy or objectStandalone. Typed objects
//     follow a reference that lets the decoder create them and provides
//     their decoder (see writeObjects); standalone objects, for which the
//     encoder found no such order, are typed objects with their type and
//     length, which the decoder holds until it has their decoder.
//   - Typed objects are encoded by Encoder: structs as their fields, in
//     order; integers as varints; floats in little-endian; strings and byte
//     arrays as is; pointers, slices, maps and interfaces as described by
//     Encoder.pointer, Encoder.slice, EncodeMap and Encoder.iface.
//   - Values that the typed encoder doesn't handle (about 2% of the objects
//     of a typical kernel, e.g. maps and slices of types from other packages
//     whose elements the generated code can't name) are encoded by
//     encodeObject, as tagged wire.Objects, and decoded by decodeObject.
const (
	// typedFlag is set in the stream header for the typed format.
	typedFlag uint64 = 1 << 62

	// objectTyped, objectLegacy and objectStandalone precede typed
	// objects, objects encoded by encodeObject, and typed objects with
	// their type and length.
	objectTyped      = 0
	objectLegacy     = 1
	objectStandalone = 2
)

var (
	schemaOnce sync.Once
	schema     uint64
)

// schemaHash returns a hash of the names and fields of all registered types.
func schemaHash() uint64 {
	schemaOnce.Do(func() {
		names := make([]string, 0, len(globalTypeDatabase))
		for name := range globalTypeDatabase {
			names = append(names, name)
		}
		sort.Strings(names)
		h := fnv.New64a()
		for _, name := range names {
			h.Write([]byte(name))
			h.Write([]byte{0})
			for _, f := range reverseTypeDatabase[globalTypeDatabase[name]].Fields {
				h.Write([]byte(f))
				h.Write([]byte{1})
			}
		}
		schema = h.Sum64()
	})
	return schema
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

// IsTyped returns true if length, an object header length returned by
// ReadHeader, starts an object graph in the typed format. Decoding the typed
// format requires the Go types, so it can't be printed by pretty.
func IsTyped(length uint64) bool {
	return length&typedFlag != 0
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
