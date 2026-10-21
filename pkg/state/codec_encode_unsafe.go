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
	"math"
	"reflect"
	"unsafe"

	"gvisor.dev/gvisor/pkg/state/wire"
)

// Encoder encodes values directly in their serialized form. It is used by
// generated StateEncode methods.
//
// The encoding is the one produced by encodeObject followed by wire.Save,
// except that references (which may change until the whole object graph has
// been resolved) and values encoded by encodeObject are embedded as
// wire.Objects, serialized when the object is.
type Encoder struct {
	es *encodeState

	// buf is the serialized data.
	buf []byte

	// objs are the embedded objects.
	objs []wire.Embedded

	// top is true for es.enc, which encodes top-level objects and records
	// the encodings of structs nested in them in es.spans.
	top bool
}

const (
	// maxArenaSize is the maximum size of the arenas used to encode objects.
	// Arenas start small, so that small object graphs are cheap to save.
	maxArenaSize = 32 << 10

	// minArenaSpace is the minimum space left in an arena to start encoding
	// an object in it.
	minArenaSpace = 256
)

// structKey identifies a Codec struct value by address and TypeIndex.
type structKey struct {
	addr  uintptr
	index uint32
}

// structSpan records the encoding of a struct value nested in a top-level
// object encoded by es.enc. It contains no pointers, so that recording one for
// every struct costs little.
type structSpan struct {
	key              structKey
	start, end       int32
	objStart, objEnd int32
}

// Context returns the context object provided at save time.
func (e *Encoder) Context() context.Context {
	return e.es.ctx
}

// tag appends tag if m includes tags.
func (e *Encoder) tag(tag wire.Tag, m Mode) {
	if m.tagged() {
		e.buf = append(e.buf, byte(tag)) // All tags are < 0x80.
	}
}

// nil_ appends a Nil value.
func (e *Encoder) nil_() {
	e.buf = append(e.buf, byte(wire.TagNil))
}

// embed embeds obj.
func (e *Encoder) embed(obj wire.Object, m Mode) {
	e.objs = append(e.objs, wire.Embedded{
		Off:      len(e.buf),
		Obj:      obj,
		Untagged: !m.tagged(),
	})
}

// embedRaw appends a copy of r, which has tag r.Tag.
func (e *Encoder) embedRaw(r *wire.Raw, m Mode) {
	e.tag(r.Tag, m)
	off := len(e.buf)
	e.buf = append(e.buf, r.Data...)
	for _, o := range r.Objects {
		o.Off += off
		e.objs = append(e.objs, o)
	}
}

// legacy encodes obj using encodeObject.
func (e *Encoder) legacy(obj reflect.Value, m Mode) {
	var encoded wire.Object
	e.es.encodeObject(obj, m.strategy(), &encoded)
	e.embed(encoded, m)
}

// newRef allocates a wire.Ref.
func (es *encodeState) newRef() *wire.Ref {
	if len(es.refArena) == cap(es.refArena) {
		es.refArena = make([]wire.Ref, 0, min(max(2*cap(es.refArena), 16), 256))
	}
	es.refArena = es.refArena[:len(es.refArena)+1]
	return &es.refArena[len(es.refArena)-1]
}

// nilRef appends a nil reference.
func (e *Encoder) nilRef(m Mode) {
	e.tag(wire.TagRef, m)
	e.buf = append(e.buf, 0, 0) // Root and number of dots.
}

// ref appends a reference to the object of type typ at addr.
//
// Precondition: addr != nil.
func (e *Encoder) ref(addr unsafe.Pointer, typ reflect.Type, m Mode, enc objectEncodeFunc, encArg any) {
	r := e.es.newRef()
	e.es.resolve(reflect.NewAt(typ, addr), r, enc, encArg)
	e.embed(r, m)
}

// typeEntryFor returns the type entry for the Codec type typ with the given
// TypeIndex.
func (es *encodeState) typeEntryFor(index uint32, typ reflect.Type) *typeEntry {
	if int(index) < len(es.typesByIndex) {
		if te := es.typesByIndex[index]; te != nil {
			return te
		}
	}
	te, ok := es.types.Lookup(typ)
	if te == nil {
		Failf("type %v is not registered", typ)
	}
	if !ok {
		es.pendingTypes = append(es.pendingTypes, te.Type)
	}
	if index != 0 {
		for int(index) >= len(es.typesByIndex) {
			es.typesByIndex = append(es.typesByIndex, nil)
		}
		es.typesByIndex[index] = te
	}
	return te
}

// structValue encodes the struct of type typ at addr, implementing Codec c.
func (e *Encoder) structValue(addr unsafe.Pointer, typ reflect.Type, c Codec, m Mode) {
	es := e.es
	key := structKey{uintptr(addr), c.StateTypeIndex().get()}
	if es.checkEncoded {
		// See encodeStruct: never encode a struct twice.
		if r, ok := es.encodedCodecStructs[key]; ok {
			e.tag(wire.TagStruct, m)
			start, objStart := len(e.buf), len(e.objs)
			e.embedRaw(r, ModeValueUntagged)
			e.recordSpan(key, start, objStart)
			return
		}
	}
	te := es.typeEntryFor(key.index, typ)
	e.tag(wire.TagStruct, m)
	start, objStart := len(e.buf), len(e.objs)
	e.buf = wire.AppendUint(e.buf, uint64(te.ID))
	switch n := len(te.Fields); n {
	case 0:
		e.buf = append(e.buf, byte(wire.TagNoObjects))
	case 1:
	default:
		e.buf = append(e.buf, byte(wire.TagMultipleObjects))
		e.buf = wire.AppendUint(e.buf, uint64(n))
	}
	if es.stats.enabled {
		es.stats.start(te.ID)
		defer es.stats.done()
	}
	c.StateEncode(e)
	e.recordSpan(key, start, objStart)
}

// recordSpan records the encoding of a struct, if needed.
//
// If the object being encoded is later merged into a containing object, the
// encodings of its structs must be reused when the container is encoded (see
// saveStructEncodings). If the object is a struct, it is reached as a whole
// when the container is encoded (since the container has a field or element
// of the object's type at its address), so the object's encoding is enough.
// But arrays (backing slices) are not reached as a whole: the container's
// array field is encoded element by element. Thus only the structs of array
// objects are recorded.
func (e *Encoder) recordSpan(key structKey, start, objStart int) {
	if !e.top || !e.es.currentIsArray {
		return
	}
	e.es.spans = append(e.es.spans, structSpan{
		key:      key,
		start:    int32(start),
		end:      int32(len(e.buf)),
		objStart: int32(objStart),
		objEnd:   int32(len(e.objs)),
	})
}

// encodeDeferred encodes the given top-level object.
func (es *encodeState) encodeDeferred(oes *objectEncodeState) {
	var c Codec
	if es.codecs && oes.enc == nil && oes.obj.Kind() == reflect.Struct {
		c, _ = oes.obj.Addr().Interface().(Codec)
	}
	if !es.codecs || (oes.enc == nil && c == nil) {
		es.current = oes
		es.encodeObject(oes.obj, oes.how, &oes.encoded)
		es.current = nil
		es.encoded(oes)
		return
	}

	// Encode in the remaining capacity of the arenas. If an object does not
	// fit, append moves it to its own buffer, and the next object starts a
	// new arena.
	if cap(es.arena)-len(es.arena) < minArenaSpace {
		es.arena = make([]byte, 0, min(max(2*cap(es.arena), 1024), maxArenaSize))
	}
	if cap(es.embedded)-len(es.embedded) < minArenaSpace/16 {
		es.embedded = make([]wire.Embedded, 0, min(max(2*cap(es.embedded), 32), maxArenaSize/64))
	}
	e := &es.enc
	e.buf = es.arena[len(es.arena):len(es.arena)]
	e.objs = es.embedded[len(es.embedded):len(es.embedded)]
	bufCap, objsCap := cap(e.buf), cap(e.objs)
	oes.spanStart = len(es.spans)
	es.current = oes
	es.currentIsArray = oes.obj.Kind() == reflect.Array
	es.checkEncoded = oes.containsEncoded
	if oes.enc != nil {
		oes.enc(e, oes)
	} else {
		e.structValue(oes.addr, oes.obj.Type(), c, ModeDefault)
	}
	es.checkEncoded = false
	es.current = nil
	oes.spanEnd = len(es.spans)
	oes.encoded = nil
	oes.raw.Data = e.buf[:len(e.buf):len(e.buf)]
	es.encodedBytes += len(e.buf)
	if cap(e.buf) == bufCap {
		es.arena = es.arena[:len(es.arena)+len(e.buf)]
	} else {
		es.arena = es.arena[:cap(es.arena)] // Start a new arena next.
	}
	oes.raw.Objects = nil
	if len(e.objs) > 0 {
		oes.raw.Objects = e.objs[:len(e.objs):len(e.objs)]
	}
	if cap(e.objs) == objsCap {
		es.embedded = es.embedded[:len(es.embedded)+len(e.objs)]
	} else {
		es.embedded = es.embedded[:cap(es.embedded)]
	}
	e.buf, e.objs = nil, nil
	es.encoded(oes)
}

// encoded is called when oes has been encoded.
func (es *encodeState) encoded(oes *objectEncodeState) {
	oes.encodedOnce = true
	if oes.absorbedWhileEncoding {
		es.saveStructEncodings(oes)
	}
}

// absorb is called when oes is merged into the containing object container.
func (es *encodeState) absorb(container, oes *objectEncodeState) {
	if oes.containsEncoded {
		// The encodings that oes would have reused are now within
		// container.
		container.containsEncoded = true
	}
	if oes == es.current {
		oes.absorbedWhileEncoding = true
		container.containsEncoded = true
		return
	}
	if !oes.encodedOnce {
		return
	}
	container.containsEncoded = true
	es.saveStructEncodings(oes)
}

// saveStructEncodings saves the encodings of the Codec structs encoded as part
// of oes, so that they can be reused by containing objects.
func (es *encodeState) saveStructEncodings(oes *objectEncodeState) {
	if es.encodedCodecStructs == nil {
		es.encodedCodecStructs = make(map[structKey]*wire.Raw)
	}
	if oes.encoded == nil && oes.obj.Kind() == reflect.Struct && len(oes.raw.Data) > 0 && wire.Tag(oes.raw.Data[0]) == wire.TagStruct {
		// The object is a Codec struct encoded by encodeDeferred.
		key := structKey{uintptr(oes.addr), oes.obj.Addr().Interface().(Codec).StateTypeIndex().get()}
		if _, ok := es.encodedCodecStructs[key]; !ok {
			r := &wire.Raw{Tag: wire.TagStruct, Data: oes.raw.Data[1:]}
			for _, o := range oes.raw.Objects {
				o.Off--
				r.Objects = append(r.Objects, o)
			}
			es.encodedCodecStructs[key] = r
		}
	}
	for _, span := range es.spans[oes.spanStart:oes.spanEnd] {
		r := &wire.Raw{
			Tag:  wire.TagStruct,
			Data: oes.raw.Data[span.start:span.end:span.end],
		}
		for _, o := range oes.raw.Objects[span.objStart:span.objEnd] {
			o.Off -= int(span.start)
			r.Objects = append(r.Objects, o)
		}
		if _, ok := es.encodedCodecStructs[span.key]; !ok {
			es.encodedCodecStructs[span.key] = r
		}
	}
}

// encodeCodecStruct encodes a Codec struct for encodeStruct.
func (es *encodeState) encodeCodecStruct(obj reflect.Value, c Codec) *wire.Raw {
	key := structKey{obj.Addr().Pointer(), c.StateTypeIndex().get()}
	if r, ok := es.encodedCodecStructs[key]; ok {
		return r
	}
	e := Encoder{es: es}
	e.structValue(obj.Addr().UnsafePointer(), obj.Type(), c, ModeValueUntagged)
	r := &wire.Raw{Tag: wire.TagStruct, Data: e.buf, Objects: e.objs}
	if es.encodedCodecStructs == nil {
		es.encodedCodecStructs = make(map[structKey]*wire.Raw)
	}
	es.encodedCodecStructs[key] = r
	return r
}

// EncodeBool encodes a bool.
func EncodeBool[T ~bool](e *Encoder, p *T, m Mode) {
	v := *p
	if !v && m == ModeDefault {
		e.nil_()
		return
	}
	e.tag(wire.TagBool, m)
	if v {
		e.buf = append(e.buf, 1)
	} else {
		e.buf = append(e.buf, 0)
	}
}

// EncodeInt encodes a signed integer.
func EncodeInt[T Signed](e *Encoder, p *T, m Mode) {
	v := *p
	if v == 0 && m == ModeDefault {
		e.nil_()
		return
	}
	e.tag(wire.TagInt, m)
	e.buf = wire.AppendInt(e.buf, int64(v))
}

// EncodeUint encodes an unsigned integer.
func EncodeUint[T Unsigned](e *Encoder, p *T, m Mode) {
	v := *p
	if v == 0 && m == ModeDefault {
		e.nil_()
		return
	}
	e.tag(wire.TagUint, m)
	e.buf = wire.AppendUint(e.buf, uint64(v))
}

// EncodeFloat32 encodes a float32.
func EncodeFloat32[T ~float32](e *Encoder, p *T, m Mode) {
	v := float32(*p)
	if math.Float32bits(v) == 0 && m == ModeDefault {
		e.nil_()
		return
	}
	e.tag(wire.TagFloat32, m)
	e.buf = wire.AppendFloat32(e.buf, v)
}

// EncodeFloat64 encodes a float64.
func EncodeFloat64[T ~float64](e *Encoder, p *T, m Mode) {
	v := float64(*p)
	if math.Float64bits(v) == 0 && m == ModeDefault {
		e.nil_()
		return
	}
	e.tag(wire.TagFloat64, m)
	e.buf = wire.AppendFloat64(e.buf, v)
}

// EncodeComplex64 encodes a complex64.
func EncodeComplex64[T ~complex64](e *Encoder, p *T, m Mode) {
	v := complex64(*p)
	re, im := real(v), imag(v)
	if math.Float32bits(re) == 0 && math.Float32bits(im) == 0 && m == ModeDefault {
		e.nil_()
		return
	}
	e.tag(wire.TagComplex64, m)
	e.buf = wire.AppendFloat32(e.buf, re)
	e.buf = wire.AppendFloat32(e.buf, im)
}

// EncodeComplex128 encodes a complex128.
func EncodeComplex128[T ~complex128](e *Encoder, p *T, m Mode) {
	v := complex128(*p)
	re, im := real(v), imag(v)
	if math.Float64bits(re) == 0 && math.Float64bits(im) == 0 && m == ModeDefault {
		e.nil_()
		return
	}
	e.tag(wire.TagComplex128, m)
	e.buf = wire.AppendFloat64(e.buf, re)
	e.buf = wire.AppendFloat64(e.buf, im)
}

// EncodeString encodes a string.
func EncodeString[T ~string](e *Encoder, p *T, m Mode) {
	v := string(*p)
	if len(v) == 0 && m == ModeDefault {
		e.nil_()
		return
	}
	e.tag(wire.TagString, m)
	e.buf = wire.AppendString(e.buf, v)
}

// EncodePointer encodes a pointer.
func EncodePointer[P ~*T, T any](e *Encoder, p *P, m Mode) {
	e.pointer(unsafe.Pointer(*p), typeOf[T](), m)
}

// pointer encodes a pointer to an object of type typ.
func (e *Encoder) pointer(v unsafe.Pointer, typ reflect.Type, m Mode) {
	if v == nil {
		if m == ModeDefault {
			e.nil_()
		} else {
			e.nilRef(m)
		}
		return
	}
	e.ref(v, typ, m, nil, nil)
}

// encodeArrayObject is an objectEncodeFunc for arrays backing []T slices.
func encodeArrayObject[T any](e *Encoder, oes *objectEncodeState) {
	elem := oes.encArg.(func(*Encoder, *T, Mode))
	a := unsafe.Slice((*T)(oes.addr), oes.obj.Len())
	EncodeArray(e, a, ModeDefault, elem)
}

// EncodeSlice encodes a slice whose elements are encoded by elem.
func EncodeSlice[S ~[]T, T any](e *Encoder, p *S, m Mode, elem func(*Encoder, *T, Mode)) {
	s := []T(*p)
	// See arrayFromSlice.
	clear(s[len(s):cap(s)])
	e.slice(unsafe.Pointer(unsafe.SliceData(s)), len(s), cap(s), s == nil, typeOf[T](), m, encodeArrayObject[T], elem)
}

// slice encodes a slice of elements of type elemTyp. The backing array is
// encoded by enc.
func (e *Encoder) slice(data unsafe.Pointer, length, capacity int, isNil bool, elemTyp reflect.Type, m Mode, enc objectEncodeFunc, encArg any) {
	if isNil {
		if m == ModeDefault {
			e.nil_()
			return
		}
		e.tag(wire.TagSlice, m)
		e.buf = append(e.buf, 0, 0, 0, 0) // Length, capacity, nil reference.
		return
	}
	e.tag(wire.TagSlice, m)
	e.buf = wire.AppendUint(e.buf, uint64(length))
	e.buf = wire.AppendUint(e.buf, uint64(capacity))
	e.ref(data, reflect.ArrayOf(capacity, elemTyp), ModeValueUntagged, enc, encArg)
}

// byteArray encodes an array of n elements of kind uint8 at p.
func (e *Encoder) byteArray(p unsafe.Pointer, n int, m Mode) {
	EncodeArray(e, unsafe.Slice((*uint8)(p), n), m, EncodeUint[uint8])
}

// encodeByteArrayObject is an objectEncodeFunc for arrays backing slices of
// elements of kind uint8.
func encodeByteArrayObject(e *Encoder, oes *objectEncodeState) {
	e.byteArray(oes.addr, oes.obj.Len(), ModeDefault)
}

// byteSlice encodes the slice of elements of kind uint8 at p, of type typ.
func (e *Encoder) byteSlice(p unsafe.Pointer, typ reflect.Type, m Mode) {
	s := *(*[]byte)(p)
	// See arrayFromSlice.
	clear(s[len(s):cap(s)])
	e.slice(unsafe.Pointer(unsafe.SliceData(s)), len(s), cap(s), s == nil, typ.Elem(), m, encodeByteArrayObject, nil)
}

// emptyStruct encodes a struct without fields of type typ, as encodeStruct
// does.
func (e *Encoder) emptyStruct(typ reflect.Type, up unsafe.Pointer, m Mode) {
	if te, _ := e.es.types.Lookup(typ); te != nil {
		// Registered types are encoded with their type ID.
		e.legacy(reflect.NewAt(typ, up).Elem(), m)
		return
	}
	e.tag(wire.TagStruct, m)
	e.buf = append(e.buf, 0, byte(wire.TagNoObjects)) // Type ID and fields.
}

// primitiveZeroKind describes how to check whether an array of primitives is
// zero.
type primitiveZeroKind uint8

const (
	notPrimitiveZero primitiveZeroKind = iota
	bytesZero
	stringsZero
	reflectZero
)

// zeroKind returns how to check whether an array with elements of type typ is
// the zero value, matching isPrimitiveZero(typ) && obj.IsZero().
func zeroKind(typ reflect.Type) primitiveZeroKind {
	switch typ.Kind() {
	case reflect.Struct:
		return notPrimitiveZero
	case reflect.String:
		return stringsZero
	case reflect.Array:
		if !isPrimitiveZero(typ) {
			return notPrimitiveZero
		}
		return reflectZero
	default:
		return bytesZero
	}
}

// arrayIsZero returns true if a should be encoded as Nil by ModeDefault.
func arrayIsZero[T any](a []T) bool {
	switch zeroKind(typeOf[T]()) {
	case notPrimitiveZero:
		return false
	case bytesZero:
		if len(a) == 0 {
			return true
		}
		b := unsafe.Slice((*byte)(unsafe.Pointer(&a[0])), uintptr(len(a))*unsafe.Sizeof(a[0]))
		for _, x := range b {
			if x != 0 {
				return false
			}
		}
		return true
	case stringsZero:
		for i := range a {
			if len(*(*string)(unsafe.Pointer(&a[i]))) != 0 {
				return false
			}
		}
		return true
	default:
		for i := range a {
			if !reflect.ValueOf(&a[i]).Elem().IsZero() {
				return false
			}
		}
		return true
	}
}

// EncodeArray encodes an array (passed as a slice of the whole array) whose
// elements are encoded by elem.
func EncodeArray[T any](e *Encoder, a []T, m Mode, elem func(*Encoder, *T, Mode)) {
	if m == ModeDefault && arrayIsZero(a) {
		e.nil_()
		return
	}
	if typeOf[T]().Kind() == reflect.Uint8 {
		// See encodeArray.
		e.tag(wire.TagBytes, m)
		e.buf = wire.AppendUint(e.buf, uint64(len(a)))
		if len(a) > 0 {
			e.buf = append(e.buf, unsafe.Slice((*byte)(unsafe.Pointer(&a[0])), len(a))...)
		}
		return
	}
	e.tag(wire.TagArray, m)
	e.buf = wire.AppendUint(e.buf, uint64(len(a)))
	for i := range a {
		elem(e, &a[i], elemMode(i))
	}
}

// mapEncoder holds what is needed to encode a map object.
type mapEncoder[K comparable, V any] struct {
	m   map[K]V
	key func(*Encoder, *K, Mode)
	val func(*Encoder, *V, Mode)
}

// encodeMapObject is an objectEncodeFunc for maps.
func encodeMapObject[K comparable, V any](e *Encoder, oes *objectEncodeState) {
	me := oes.encArg.(*mapEncoder[K, V])
	e.tag(wire.TagMap, ModeDefault)
	e.buf = wire.AppendUint(e.buf, uint64(len(me.m)))
	i := 0
	for k, v := range me.m {
		me.key(e, &k, elemMode(i))
		me.val(e, &v, elemMode(i))
		i++
	}
}

// EncodeMap encodes a map whose keys and values are encoded by key and val.
func EncodeMap[M ~map[K]V, K comparable, V any](e *Encoder, p *M, m Mode, key func(*Encoder, *K, Mode), val func(*Encoder, *V, Mode)) {
	v := map[K]V(*p)
	if v == nil {
		if m == ModeDefault {
			e.nil_()
		} else {
			e.nilRef(m)
		}
		return
	}
	r := e.es.newRef()
	// Use the map's own type, as encodeObject does.
	e.es.resolve(reflect.ValueOf(*p), r, encodeMapObject[K, V], &mapEncoder[K, V]{v, key, val})
	e.embed(r, m)
}

// typeSpec returns the encoded type specification of typ.
func (es *encodeState) typeSpec(typ reflect.Type) []byte {
	if b, ok := es.typeSpecs[typ]; ok {
		return b
	}
	b := wire.AppendTypeSpec(nil, es.findType(typ))
	if es.typeSpecs == nil {
		es.typeSpecs = make(map[reflect.Type][]byte)
	}
	es.typeSpecs[typ] = b
	return b
}

// EncodeInterface encodes an interface.
func EncodeInterface[T any](e *Encoder, p *T, m Mode) {
	e.iface(any(*p), m)
}

// iface encodes the interface value v.
func (e *Encoder) iface(v any, m Mode) {
	if v == nil {
		if m == ModeDefault {
			e.nil_()
			return
		}
		e.tag(wire.TagInterface, m)
		e.buf = append(e.buf, byte(wire.TypeSpecTagNil), byte(wire.TagNil))
		return
	}
	typ := reflect.TypeOf(v)
	spec := e.es.typeSpec(typ)
	e.tag(wire.TagInterface, m)
	e.buf = append(e.buf, spec...)
	if typ.Kind() == reflect.Ptr {
		e.pointer(reflect.ValueOf(v).UnsafePointer(), typ.Elem(), ModeValue)
		return
	}
	e.legacy(reflect.ValueOf(v), ModeValue)
}

// EncodeValue encodes a value of any type. It is used for elements whose kind
// is not known to go_stateify.
func EncodeValue[T any](e *Encoder, p *T, m Mode) {
	e.value(unsafe.Pointer(p), typeOf[T](), any(p), m)
}

// EncodeAny is EncodeValue for p of type *T, without instantiating code for
// each type T. It is used for fields whose kind is not known to go_stateify.
func EncodeAny(e *Encoder, p any, m Mode) {
	rv := reflect.ValueOf(p)
	e.value(rv.UnsafePointer(), rv.Type().Elem(), p, m)
}

// value implements EncodeValue for the value of type typ at up. pi is a
// pointer to it.
func (e *Encoder) value(up unsafe.Pointer, typ reflect.Type, pi any, m Mode) {
	if c, ok := pi.(Codec); ok && typ.Kind() == reflect.Struct {
		e.structValue(up, typ, c, m)
		return
	}
	switch typ.Kind() {
	case reflect.Bool:
		EncodeBool(e, (*bool)(up), m)
	case reflect.Int:
		EncodeInt(e, (*int)(up), m)
	case reflect.Int8:
		EncodeInt(e, (*int8)(up), m)
	case reflect.Int16:
		EncodeInt(e, (*int16)(up), m)
	case reflect.Int32:
		EncodeInt(e, (*int32)(up), m)
	case reflect.Int64:
		EncodeInt(e, (*int64)(up), m)
	case reflect.Uint:
		EncodeUint(e, (*uint)(up), m)
	case reflect.Uint8:
		EncodeUint(e, (*uint8)(up), m)
	case reflect.Uint16:
		EncodeUint(e, (*uint16)(up), m)
	case reflect.Uint32:
		EncodeUint(e, (*uint32)(up), m)
	case reflect.Uint64:
		EncodeUint(e, (*uint64)(up), m)
	case reflect.Uintptr:
		EncodeUint(e, (*uintptr)(up), m)
	case reflect.Float32:
		EncodeFloat32(e, (*float32)(up), m)
	case reflect.Float64:
		EncodeFloat64(e, (*float64)(up), m)
	case reflect.Complex64:
		EncodeComplex64(e, (*complex64)(up), m)
	case reflect.Complex128:
		EncodeComplex128(e, (*complex128)(up), m)
	case reflect.String:
		EncodeString(e, (*string)(up), m)
	case reflect.Interface:
		e.iface(reflect.NewAt(typ, up).Elem().Interface(), m)
	case reflect.Ptr:
		e.pointer(*(*unsafe.Pointer)(up), typ.Elem(), m)
	case reflect.Slice:
		if typ.Elem().Kind() != reflect.Uint8 {
			e.legacy(reflect.NewAt(typ, up).Elem(), m)
			return
		}
		e.byteSlice(up, typ, m)
	case reflect.Array:
		if typ.Elem().Kind() != reflect.Uint8 {
			e.legacy(reflect.NewAt(typ, up).Elem(), m)
			return
		}
		e.byteArray(up, typ.Len(), m)
	case reflect.Struct:
		if typ.NumField() != 0 {
			e.legacy(reflect.NewAt(typ, up).Elem(), m)
			return
		}
		e.emptyStruct(typ, up, m)
	default:
		e.legacy(reflect.NewAt(typ, up).Elem(), m)
	}
}

// Detach returns an Encoder that encodes a single value (with ModeDefault)
// separately from e. It is used by StateEncode for fields saved through a
// value, which are encoded before all other fields (as by StateSave); Finish
// and EmbedValue then place the result.
func (e *Encoder) Detach() *Encoder {
	return &Encoder{es: e.es}
}

// Finish returns the value encoded by a detached Encoder.
func (e *Encoder) Finish() wire.Object {
	if len(e.buf) == 0 {
		// The value was encoded by encodeObject.
		if len(e.objs) != 1 || e.objs[0].Off != 0 || e.objs[0].Untagged {
			Failf("invalid detached encoding")
		}
		return e.objs[0].Obj
	}
	r := &wire.Raw{Tag: wire.Tag(e.buf[0]), Data: e.buf[1:]}
	for _, o := range e.objs {
		o.Off--
		r.Objects = append(r.Objects, o)
	}
	return r
}

// EncodeLegacyValue encodes v as Sink.SaveValue does, for fields saved
// through a value of a type that go_stateify can't parse.
func EncodeLegacyValue(e *Encoder, v any) wire.Object {
	var encoded wire.Object
	e.es.encodeObject(reflect.ValueOf(v), encodeDefault, &encoded)
	return encoded
}

// EmbedValue embeds the result of Finish or EncodeLegacyValue as the next
// field.
func EmbedValue(e *Encoder, obj wire.Object) {
	e.embed(obj, ModeDefault)
}
