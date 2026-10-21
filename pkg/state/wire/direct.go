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

package wire

import (
	"fmt"
	"math"

	"gvisor.dev/gvisor/pkg/gohacks"
)

// This file contains helpers used by the state package to encode and decode
// objects directly to and from their serialized form, without building a tree
// of Objects. The serialized form is identical to the one produced by Save and
// consumed by Load.

// Tag identifies the type of a serialized Object. A serialized Object is its
// Tag followed by its contents, except for elements of an Array or Map after
// the first one, which omit the Tag (they share the first element's).
type Tag = Uint

// Tags of serialized Objects.
const (
	TagBool            = typeBool
	TagInt             = typeInt
	TagUint            = typeUint
	TagFloat32         = typeFloat32
	TagFloat64         = typeFloat64
	TagNil             = typeNil
	TagRef             = typeRef
	TagString          = typeString
	TagSlice           = typeSlice
	TagArray           = typeArray
	TagMap             = typeMap
	TagStruct          = typeStruct
	TagNoObjects       = typeNoObjects
	TagMultipleObjects = typeMultipleObjects
	TagInterface       = typeInterface
	TagComplex64       = typeComplex64
	TagComplex128      = typeComplex128
	TagType            = typeType
	TagBytes           = typeBytes
)

// TypeSpec tags, as written by saveTypeSpec.
const (
	TypeSpecTagID      = typeSpecTypeID
	TypeSpecTagPointer = typeSpecPointer
	TypeSpecTagNil     = typeSpecNil
)

// AppendUint appends the encoding of a Uint.
func AppendUint(b []byte, u uint64) []byte {
	for u >= 0x80 {
		b = append(b, byte(u)|0x80)
		u >>= 7
	}
	return append(b, byte(u))
}

// AppendInt appends the encoding of an Int.
func AppendInt(b []byte, i int64) []byte {
	u := uint64(i) << 1
	if i < 0 {
		u = ^u
	}
	return AppendUint(b, u)
}

// AppendFloat32 appends the encoding of a Float32.
func AppendFloat32(b []byte, f float32) []byte {
	return AppendUint(b, uint64(math.Float32bits(f)))
}

// AppendFloat64 appends the encoding of a Float64.
func AppendFloat64(b []byte, f float64) []byte {
	return AppendUint(b, math.Float64bits(f))
}

// AppendString appends the encoding of a String.
func AppendString(b []byte, s string) []byte {
	b = AppendUint(b, uint64(len(s)))
	return append(b, s...)
}

// AppendTypeSpec appends the encoding of a TypeSpec.
func AppendTypeSpec(b []byte, t TypeSpec) []byte {
	switch x := t.(type) {
	case TypeID:
		b = AppendUint(b, uint64(typeSpecTypeID))
		return AppendUint(b, uint64(x))
	case *TypeSpecPointer:
		b = AppendUint(b, uint64(typeSpecPointer))
		return AppendTypeSpec(b, x.Type)
	case *TypeSpecArray:
		b = AppendUint(b, uint64(typeSpecArray))
		b = AppendUint(b, uint64(x.Count))
		return AppendTypeSpec(b, x.Type)
	case *TypeSpecSlice:
		b = AppendUint(b, uint64(typeSpecSlice))
		return AppendTypeSpec(b, x.Type)
	case *TypeSpecMap:
		b = AppendUint(b, uint64(typeSpecMap))
		b = AppendTypeSpec(b, x.Key)
		return AppendTypeSpec(b, x.Value)
	case TypeSpecNil:
		return AppendUint(b, uint64(typeSpecNil))
	default:
		panic(fmt.Errorf("unknown type %T", t))
	}
}

// Embedded is an Object embedded in a Raw object at a given offset.
type Embedded struct {
	// Off is the offset in Raw.Data before which Obj is serialized.
	Off int

	// Obj is the embedded Object.
	Obj Object

	// Untagged indicates that Obj is an Array or Map element after the
	// first one, and is serialized without its Tag.
	Untagged bool
}

// Raw is an Object that has already been serialized, except for a set of
// embedded Objects that are serialized when Raw is (typically because they
// are references that can still change).
type Raw struct {
	// Tag is the Tag of the serialized Object.
	Tag Tag

	// Data is the serialized contents, without the Tag.
	Data []byte

	// Objects are the embedded Objects, sorted by offset.
	Objects []Embedded
}

// save implements Object.save.
func (r *Raw) save(w *Writer) {
	off := 0
	for i := range r.Objects {
		e := &r.Objects[i]
		w.write(r.Data[off:e.Off])
		off = e.Off
		if e.Untagged {
			e.Obj.save(w)
		} else {
			Save(w, e.Obj)
		}
	}
	w.write(r.Data[off:])
}

// load implements Object.load.
func (*Raw) load(r *Reader) Object {
	panic("Raw objects cannot be loaded")
}

// SaveRawData saves r without its Tag. This is used for Raw objects whose Data
// includes the tag.
func SaveRawData(w *Writer, r *Raw) {
	r.save(w)
}

// ReadUint reads a Uint (or Tag).
func ReadUint(r *Reader) uint64 {
	return uint64(loadUint(r))
}

// ReadInt reads an Int.
func ReadInt(r *Reader) int64 {
	return int64(loadInt(r))
}

// ReadString reads a String.
func ReadString(r *Reader) string {
	return string(loadString(r))
}

// ReadFloat32 reads a Float32.
func ReadFloat32(r *Reader) float32 {
	return float32(loadFloat32(r))
}

// ReadFloat64 reads a Float64.
func ReadFloat64(r *Reader) float64 {
	return float64(loadFloat64(r))
}

// ReadDots reads n reference Dots, as in a Ref.
func ReadDots(r *Reader, n uint64) []Dot {
	dots := make([]Dot, n)
	for i := range dots {
		d := loadInt(r)
		if d >= 0 {
			dots[i] = Index(d)
			continue
		}
		p := make([]byte, -d)
		readFull(r, p)
		fieldName := FieldName(gohacks.StringFromImmutableBytes(p))
		dots[i] = &fieldName
	}
	return dots
}

// ReadTypeSpecBody reads the rest of a TypeSpec whose header has been read.
func ReadTypeSpecBody(r *Reader, hdr Uint) TypeSpec {
	return loadTypeBody(r, hdr)
}

// ReadTypeSpec reads a TypeSpec.
func ReadTypeSpec(r *Reader) TypeSpec {
	return loadType(r)
}

// LoadTagged loads the contents of an Object whose Tag has been read.
func LoadTagged(r *Reader, tag Tag) Object {
	return loadPayload(r, tag)
}

// LoadStructFields loads the fields of a Struct whose Tag and TypeID have been
// read.
func LoadStructFields(r *Reader, id TypeID) *Struct {
	return &Struct{TypeID: id, fields: Load(r)}
}

// LoadStructFieldsTagged is like LoadStructFields, but the Tag of the fields
// object has already been read.
func LoadStructFieldsTagged(r *Reader, id TypeID, tag Tag) *Struct {
	return &Struct{TypeID: id, fields: LoadTagged(r, tag)}
}

// ReadFull reads exactly len(p) bytes. It panics on error.
func ReadFull(r *Reader, p []byte) {
	readFull(r, p)
}
