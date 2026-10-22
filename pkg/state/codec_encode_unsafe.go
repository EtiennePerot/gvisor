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
	"encoding/binary"
	"math"
	"reflect"
	"unsafe"

	"gvisor.dev/gvisor/pkg/state/wire"
)

// Encoder encodes values in the typed format. It is used by generated
// StateEncode methods.
//
// In the typed format, values are encoded without tags or headers: the
// decoder knows their types statically. See codec.go.
type Encoder struct {
	es *encodeState

	// buf is the serialized data.
	buf []byte

	// objs are the embedded references and values.
	objs []embedded

	// top is true for es.enc, which encodes top-level objects and records
	// the encodings of structs nested in them in es.spans.
	top bool
}

// embedded is a value embedded in an encoding, which is only serialized when
// the encoding is written: a reference to an object (when typ != nil), or a
// value encoded by encodeObject (a tagged wire.Object, otherwise).
//
// References are resolved when written, once all objects are known, since
// the object containing an address may change until then (see resolve).
type embedded struct {
	// off is the offset in the encoding before which the value is written.
	off int

	// addr and typ are the address and type of the referenced object.
	addr uintptr
	typ  reflect.Type

	// oes is the object containing the referenced object when it was
	// resolved. It may have been absorbed since.
	oes *objectEncodeState

	// decoder is set if the reference provides the decoder of the
	// object, because it was created by typed code (see writeObjects).
	decoder bool

	// obj is the embedded wire.Object.
	obj wire.Object
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
// object encoded by es.enc.
type structSpan struct {
	key              structKey
	start, end       int32
	objStart, objEnd int32
}

// encodedStruct is a saved encoding of a struct, with offsets of embedded
// values relative to its start.
type encodedStruct struct {
	data []byte
	objs []embedded
}

// Context returns the context object provided at save time.
func (e *Encoder) Context() context.Context {
	return e.es.ctx
}

// legacy encodes obj using encodeObject, embedding the result.
func (e *Encoder) legacy(obj reflect.Value) {
	var encoded wire.Object
	e.es.encodeObject(obj, encodeDefault, &encoded)
	e.objs = append(e.objs, embedded{off: len(e.buf), obj: encoded})
}

// ref resolves the object of type typ at addr and embeds a reference to it.
//
// Precondition: addr != nil.
func (e *Encoder) ref(addr unsafe.Pointer, typ reflect.Type, enc typedEncoder, encArg any) {
	oes := e.es.resolve(reflect.NewAt(typ, addr), nil, enc, encArg)
	e.objs = append(e.objs, embedded{off: len(e.buf), addr: uintptr(addr), typ: typ, oes: oes, decoder: enc != nil})
}

// structValue encodes the struct of type typ at addr, implementing Codec c.
func (e *Encoder) structValue(addr unsafe.Pointer, typ reflect.Type, c Codec) {
	es := e.es
	key := structKey{uintptr(addr), c.StateTypeIndex().get()}
	if es.checkEncoded {
		// Never encode a struct twice; see saveStructEncodings.
		if s, ok := es.encodedCodecStructs[key]; ok {
			start, objStart := len(e.buf), len(e.objs)
			e.buf = append(e.buf, s.data...)
			for _, o := range s.objs {
				o.off += start
				e.objs = append(e.objs, o)
			}
			e.recordSpan(key, start, objStart)
			return
		}
	}
	start, objStart := len(e.buf), len(e.objs)
	if es.stats.enabled {
		te := es.typeEntryFor(key.index, typ)
		es.stats.start(te.ID)
		defer es.stats.done()
	}
	c.StateEncode(e)
	e.recordSpan(key, start, objStart)
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
		es.embedded = make([]embedded, 0, min(max(2*cap(es.embedded), 32), maxArenaSize/64))
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
		oes.enc.encode(e, oes)
	} else {
		e.structValue(oes.addr, oes.obj.Type(), c)
	}
	es.checkEncoded = false
	es.current = nil
	oes.spanEnd = len(es.spans)
	oes.encoded = nil
	oes.data = e.buf[:len(e.buf):len(e.buf)]
	es.encodedBytes += len(e.buf)
	if cap(e.buf) == bufCap {
		es.arena = es.arena[:len(es.arena)+len(e.buf)]
	} else {
		es.arena = es.arena[:cap(es.arena)] // Start a new arena next.
	}
	oes.objs = nil
	if len(e.objs) > 0 {
		oes.objs = e.objs[:len(e.objs):len(e.objs)]
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
	oes.container = container
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
// of oes, so that they can be reused by containing objects: StateEncode may
// have side effects (beforeSave, or creating objects saved through values),
// so it must be called once per struct.
func (es *encodeState) saveStructEncodings(oes *objectEncodeState) {
	if es.encodedCodecStructs == nil {
		es.encodedCodecStructs = make(map[structKey]encodedStruct)
	}
	if oes.encoded == nil && oes.obj.Kind() == reflect.Struct {
		// The object is a Codec struct encoded by encodeDeferred.
		key := structKey{uintptr(oes.addr), oes.obj.Addr().Interface().(Codec).StateTypeIndex().get()}
		if _, ok := es.encodedCodecStructs[key]; !ok {
			es.encodedCodecStructs[key] = encodedStruct{data: oes.data, objs: oes.objs}
		}
	}
	for _, span := range es.spans[oes.spanStart:oes.spanEnd] {
		s := encodedStruct{data: oes.data[span.start:span.end:span.end]}
		for _, o := range oes.objs[span.objStart:span.objEnd] {
			o.off -= int(span.start)
			s.objs = append(s.objs, o)
		}
		if _, ok := es.encodedCodecStructs[span.key]; !ok {
			es.encodedCodecStructs[span.key] = s
		}
	}
}

// EncodeBool encodes a bool.
func EncodeBool[T ~bool](e *Encoder, p *T) {
	if *p {
		e.buf = append(e.buf, 1)
	} else {
		e.buf = append(e.buf, 0)
	}
}

// EncodeInt encodes a signed integer.
func EncodeInt[T Signed](e *Encoder, p *T) {
	e.buf = wire.AppendInt(e.buf, int64(*p))
}

// EncodeUint encodes an unsigned integer.
func EncodeUint[T Unsigned](e *Encoder, p *T) {
	e.buf = wire.AppendUint(e.buf, uint64(*p))
}

// EncodeFloat32 encodes a float32.
func EncodeFloat32[T ~float32](e *Encoder, p *T) {
	e.buf = binary.LittleEndian.AppendUint32(e.buf, math.Float32bits(float32(*p)))
}

// EncodeFloat64 encodes a float64.
func EncodeFloat64[T ~float64](e *Encoder, p *T) {
	e.buf = binary.LittleEndian.AppendUint64(e.buf, math.Float64bits(float64(*p)))
}

// EncodeComplex64 encodes a complex64.
func EncodeComplex64[T ~complex64](e *Encoder, p *T) {
	v := complex64(*p)
	e.buf = binary.LittleEndian.AppendUint32(e.buf, math.Float32bits(real(v)))
	e.buf = binary.LittleEndian.AppendUint32(e.buf, math.Float32bits(imag(v)))
}

// EncodeComplex128 encodes a complex128.
func EncodeComplex128[T ~complex128](e *Encoder, p *T) {
	v := complex128(*p)
	e.buf = binary.LittleEndian.AppendUint64(e.buf, math.Float64bits(real(v)))
	e.buf = binary.LittleEndian.AppendUint64(e.buf, math.Float64bits(imag(v)))
}

// EncodeString encodes a string.
func EncodeString[T ~string](e *Encoder, p *T) {
	e.buf = wire.AppendString(e.buf, string(*p))
}

// EncodePointer encodes a pointer.
func EncodePointer[P ~*T, T any](e *Encoder, p *P) {
	e.pointer(unsafe.Pointer(*p), typeOf[T]())
}

// pointer encodes a pointer to an object of type typ: zero for nil, or a
// reference, written by writeRef.
func (e *Encoder) pointer(v unsafe.Pointer, typ reflect.Type) {
	if v == nil {
		e.buf = append(e.buf, 0)
		return
	}
	e.ref(v, typ, nil, nil)
}

// arrayEncoder encodes arrays backing []T slices.
type arrayEncoder[T any] struct {
	elem func(*Encoder, *T)
}

// encode implements typedEncoder.encode.
func (a arrayEncoder[T]) encode(e *Encoder, oes *objectEncodeState) {
	EncodeArray(e, unsafe.Slice((*T)(oes.addr), oes.obj.Len()), a.elem)
}

// EncodeSlice encodes a slice whose elements are encoded by elem.
func EncodeSlice[S ~[]T, T any](e *Encoder, p *S, elem func(*Encoder, *T)) {
	s := []T(*p)
	// See arrayFromSlice.
	clear(s[len(s):cap(s)])
	e.slice(unsafe.Pointer(unsafe.SliceData(s)), len(s), cap(s), s == nil, typeOf[T](), arrayEncoder[T]{elem})
}

// slice encodes a slice of elements of type elemTyp: zero for nil, or its
// capacity plus one, its length and a reference to its backing array, which
// is encoded by enc.
func (e *Encoder) slice(data unsafe.Pointer, length, capacity int, isNil bool, elemTyp reflect.Type, enc typedEncoder) {
	if isNil {
		e.buf = append(e.buf, 0)
		return
	}
	e.buf = wire.AppendUint(e.buf, uint64(capacity)+1)
	e.buf = wire.AppendUint(e.buf, uint64(length))
	e.ref(data, reflect.ArrayOf(capacity, elemTyp), enc, nil)
}

// byteArray encodes an array of n elements of kind uint8 at p.
func (e *Encoder) byteArray(p unsafe.Pointer, n int) {
	e.buf = append(e.buf, unsafe.Slice((*byte)(p), n)...)
}

// byteArrayEncoder encodes arrays backing slices of elements of kind uint8.
type byteArrayEncoder struct{}

// encode implements typedEncoder.encode.
func (byteArrayEncoder) encode(e *Encoder, oes *objectEncodeState) {
	e.byteArray(oes.addr, oes.obj.Len())
}

// byteSlice encodes the slice of elements of kind uint8 at p, of type typ.
func (e *Encoder) byteSlice(p unsafe.Pointer, typ reflect.Type) {
	s := *(*[]byte)(p)
	// See arrayFromSlice.
	clear(s[len(s):cap(s)])
	e.slice(unsafe.Pointer(unsafe.SliceData(s)), len(s), cap(s), s == nil, typ.Elem(), byteArrayEncoder{})
}

// EncodeArray encodes an array (passed as a slice of the whole array) whose
// elements are encoded by elem. Arrays of bytes are copied.
func EncodeArray[T any](e *Encoder, a []T, elem func(*Encoder, *T)) {
	if len(a) == 0 {
		return
	}
	if typeOf[T]().Kind() == reflect.Uint8 {
		e.byteArray(unsafe.Pointer(&a[0]), len(a))
		return
	}
	for i := range a {
		elem(e, &a[i])
	}
}

// mapEncoder encodes maps, with key; the value encoder is in encArg.
type mapEncoder[M ~map[K]V, K comparable, V any] struct {
	key func(*Encoder, *K)
}

// encode implements typedEncoder.encode.
func (me mapEncoder[M, K, V]) encode(e *Encoder, oes *objectEncodeState) {
	val := oes.encArg.(func(*Encoder, *V))
	m := oes.obj.Interface().(M)
	e.buf = wire.AppendUint(e.buf, uint64(len(m)))
	// Reuse the same variables, which escape since the encoders take their
	// addresses, across maps of the same type. Map encoding is not
	// reentrant: map elements refer to other maps.
	kv, _ := e.es.mapScratch[oes.obj.Type()].(*mapEntry[K, V])
	if kv == nil {
		kv = new(mapEntry[K, V])
		if e.es.mapScratch == nil {
			e.es.mapScratch = make(map[reflect.Type]any)
		}
		e.es.mapScratch[oes.obj.Type()] = kv
	}
	for kv.k, kv.v = range m {
		me.key(e, &kv.k)
		val(e, &kv.v)
	}
	*kv = mapEntry[K, V]{}
}

// mapEntry holds a map key and value.
type mapEntry[K, V any] struct {
	k K
	v V
}

// EncodeMap encodes a map whose keys and values are encoded by key and val: a
// zero for nil, or a reference to the map object.
func EncodeMap[M ~map[K]V, K comparable, V any](e *Encoder, p *M, key func(*Encoder, *K), val func(*Encoder, *V)) {
	if *p == nil {
		e.buf = append(e.buf, 0)
		return
	}
	// Use the map's own type, as encodeObject does.
	rv := reflect.ValueOf(*p)
	oes := e.es.resolve(rv, nil, mapEncoder[M, K, V]{key}, val)
	e.objs = append(e.objs, embedded{off: len(e.buf), addr: rv.Pointer(), typ: rv.Type(), oes: oes, decoder: true})
}

// Interface encodings: zero for nil, or a type ID shifted left by two, with
// one of the following kinds.
const (
	// ifacePointer is a non-nil pointer to the type, followed by a
	// reference.
	ifacePointer = 1

	// ifaceNilPointer is a nil pointer to the type.
	ifaceNilPointer = 2

	// ifaceLegacy is followed by a tagged wire.Object encoding the interface
	// value, for other types. The type ID is zero.
	ifaceLegacy = 3
)

// typeIDOf returns the type ID of typ, or zero if typ has no type ID.
func (es *encodeState) typeIDOf(typ reflect.Type) uint64 {
	if id, ok := es.typeIDs[typ]; ok {
		return id
	}
	var id uint64
	if te, ok := es.types.Lookup(typ); te != nil {
		if !ok {
			es.pendingTypes = append(es.pendingTypes, te.Type)
		}
		id = uint64(te.ID)
	}
	if es.typeIDs == nil {
		es.typeIDs = make(map[reflect.Type]uint64)
	}
	es.typeIDs[typ] = id
	return id
}

// EncodeInterface encodes an interface.
func EncodeInterface[T any](e *Encoder, p *T) {
	e.iface(any(*p), unsafe.Pointer(p), typeOf[T]())
}

// iface encodes the interface value v, of the interface type typ at p.
func (e *Encoder) iface(v any, p unsafe.Pointer, typ reflect.Type) {
	if v == nil {
		e.buf = append(e.buf, 0)
		return
	}
	dyn := reflect.TypeOf(v)
	if dyn.Kind() == reflect.Ptr {
		if id := e.es.typeIDOf(dyn.Elem()); id != 0 {
			ptr := reflect.ValueOf(v).UnsafePointer()
			if ptr == nil {
				e.buf = wire.AppendUint(e.buf, id<<2|ifaceNilPointer)
				return
			}
			e.buf = wire.AppendUint(e.buf, id<<2|ifacePointer)
			e.ref(ptr, dyn.Elem(), nil, nil)
			return
		}
	}
	e.buf = append(e.buf, ifaceLegacy)
	e.legacy(reflect.NewAt(typ, p).Elem())
}

// EncodeValue encodes a value of any type. It is used for elements whose kind
// is not known to go_stateify.
func EncodeValue[T any](e *Encoder, p *T) {
	e.value(unsafe.Pointer(p), typeOf[T](), any(p))
}

// EncodeAny is EncodeValue for p of type *T, without instantiating code for
// each type T. It is used for fields whose kind is not known to go_stateify.
func EncodeAny(e *Encoder, p any) {
	rv := reflect.ValueOf(p)
	e.value(rv.UnsafePointer(), rv.Type().Elem(), p)
}

// value implements EncodeValue for the value of type typ at up. pi is a
// pointer to it.
func (e *Encoder) value(up unsafe.Pointer, typ reflect.Type, pi any) {
	if c, ok := pi.(Codec); ok && typ.Kind() == reflect.Struct {
		e.structValue(up, typ, c)
		return
	}
	switch typ.Kind() {
	case reflect.Bool:
		EncodeBool(e, (*bool)(up))
	case reflect.Int:
		EncodeInt(e, (*int)(up))
	case reflect.Int8:
		EncodeInt(e, (*int8)(up))
	case reflect.Int16:
		EncodeInt(e, (*int16)(up))
	case reflect.Int32:
		EncodeInt(e, (*int32)(up))
	case reflect.Int64:
		EncodeInt(e, (*int64)(up))
	case reflect.Uint:
		EncodeUint(e, (*uint)(up))
	case reflect.Uint8:
		EncodeUint(e, (*uint8)(up))
	case reflect.Uint16:
		EncodeUint(e, (*uint16)(up))
	case reflect.Uint32:
		EncodeUint(e, (*uint32)(up))
	case reflect.Uint64:
		EncodeUint(e, (*uint64)(up))
	case reflect.Uintptr:
		EncodeUint(e, (*uintptr)(up))
	case reflect.Float32:
		EncodeFloat32(e, (*float32)(up))
	case reflect.Float64:
		EncodeFloat64(e, (*float64)(up))
	case reflect.Complex64:
		EncodeComplex64(e, (*complex64)(up))
	case reflect.Complex128:
		EncodeComplex128(e, (*complex128)(up))
	case reflect.String:
		EncodeString(e, (*string)(up))
	case reflect.Interface:
		e.iface(reflect.NewAt(typ, up).Elem().Interface(), up, typ)
	case reflect.Ptr:
		e.pointer(*(*unsafe.Pointer)(up), typ.Elem())
	case reflect.Slice:
		if typ.Elem().Kind() != reflect.Uint8 {
			e.legacy(reflect.NewAt(typ, up).Elem())
			return
		}
		e.byteSlice(up, typ)
	case reflect.Array:
		if typ.Elem().Kind() != reflect.Uint8 {
			e.legacy(reflect.NewAt(typ, up).Elem())
			return
		}
		e.byteArray(up, typ.Len())
	case reflect.Struct:
		if typ.NumField() != 0 {
			e.legacy(reflect.NewAt(typ, up).Elem())
		}
		// Structs without fields are not encoded.
	default:
		e.legacy(reflect.NewAt(typ, up).Elem())
	}
}

// EncodeLegacyValue encodes v as Sink.SaveValue does, for fields saved
// through a value of a type that go_stateify can't parse.
func EncodeLegacyValue(e *Encoder, v any) {
	e.legacy(reflect.ValueOf(v))
}

// writeRef appends the reference to the object of type typ at addr, which
// must have been resolved, to b.
func (es *encodeState) writeRef(b []byte, o *embedded) []byte {
	addr, typ, oes := o.addr, o.typ, o.oes
	if typ.Kind() != reflect.Map && typ.Size() == 0 && addr == dummyAddr {
		oes = es.zeroValues[typ]
	} else {
		// Find the object containing the referenced object now: the
		// object found by resolve may have been absorbed since.
		for oes.container != nil {
			oes = oes.container
		}
		start, otyp := uintptr(oes.addr), oes.obj.Type()
		if start != addr || otyp != typ {
			// A reference into a containing object: see resolve.
			// The decoder can create the object from its type
			// unless it needs a decoder from typed code.
			if oes.enc == nil {
				es.enqueue(oes)
			}
			b = wire.AppendUint(b, uint64(oes.id)<<1|1)
			dots := es.traverse(otyp, typ, start, addr)
			b = wire.AppendUint(b, uint64(len(dots)))
			b = wire.AppendDots(b, dots)
			return wire.AppendTypeSpec(b, es.findType(otyp))
		}
	}
	if oes.enc == nil || o.decoder {
		es.enqueue(oes)
	}
	return wire.AppendUint(b, uint64(oes.id)<<1)
}

// writeTyped writes the typed encoding of oes to es.w; see writeObjects for
// standalone.
func (es *encodeState) writeTyped(oes *objectEncodeState, standalone bool) {
	// Resolve references first, since they may add types, which must be
	// written before the object.
	b := es.refBuf[:0]
	es.refOffs = es.refOffs[:0]
	for i := range oes.objs {
		if o := &oes.objs[i]; o.typ != nil {
			b = es.writeRef(b, o)
		} else {
			wire.WalkRefs(o.obj, es.walkRef)
		}
		es.refOffs = append(es.refOffs, len(b))
	}
	es.refBuf = b
	w := &es.w
	var spec wire.TypeSpec = wire.TypeSpecNil{}
	if standalone {
		// Write the body to a buffer, to write its length first. Only
		// structs (whose decoders are always known) have their type.
		if oes.obj.Kind() == reflect.Struct {
			spec = es.findType(oes.obj.Type())
		}
		es.standaloneBuf.Reset()
		w = &wire.Writer{Writer: &es.standaloneBuf}
	}
	es.writePendingTypes()
	off, refOff := 0, 0
	if !standalone {
		wire.SaveUint(w, uint64(wire.TagUint))
		wire.SaveUint(w, uint64(oes.id))
		wire.SaveUint(w, objectTyped)
	}
	for i, o := range oes.objs {
		w.WriteBytes(oes.data[off:o.off])
		off = o.off
		if o.typ != nil {
			w.WriteBytes(b[refOff:es.refOffs[i]])
		} else {
			wire.Save(w, o.obj)
		}
		refOff = es.refOffs[i]
	}
	w.WriteBytes(oes.data[off:])
	if standalone {
		if err := w.Flush(); err != nil {
			panic(err)
		}
		wire.SaveUint(&es.w, uint64(wire.TagUint))
		wire.SaveUint(&es.w, uint64(oes.id))
		wire.SaveUint(&es.w, objectStandalone)
		es.w.WriteBytes(wire.AppendTypeSpec(nil, spec))
		wire.SaveUint(&es.w, uint64(es.standaloneBuf.Len()))
		es.w.WriteBytes(es.standaloneBuf.Bytes())
	}
}

// copyMap returns a copy of the map value obj, which doesn't alias obj.
func copyMap(obj reflect.Value) reflect.Value {
	p := new(unsafe.Pointer)
	*p = obj.UnsafePointer()
	return reflect.NewAt(obj.Type(), unsafe.Pointer(p)).Elem()
}
