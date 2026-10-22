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
	"bytes"
	"context"
	"encoding/binary"
	"math"
	"reflect"
	"unsafe"

	"gvisor.dev/gvisor/pkg/state/wire"
)

// typedDecoder decodes objects in the typed format. Implementations are
// pointer-shaped types, so that they are stored in interfaces without
// allocating (unlike closures created by generic functions).
type typedDecoder interface {
	decode(d *Decoder, ods *objectDecodeState)
}

// arrayDecoder is a typedDecoder for arrays, which can also allocate them.
type arrayDecoder interface {
	typedDecoder
	alloc(n int) unsafe.Pointer
}

// Decoder decodes values in the typed format. It is used by generated
// StateDecode methods.
//
// As with decodeObject, zero values leave the destination unchanged (this
// matters for the root object, which may already be initialized), and
// integers that do not fit their destination are errors.
type Decoder struct {
	ds *decodeState

	// ods is the object being decoded.
	ods *objectDecodeState

	// r is the input stream.
	r *wire.Reader

	// lastRef is the object referred to by the last decoded value, as found
	// by waitObject, or zero.
	lastRef objectID

	// dots and names are scratch space for target.
	dots  []dot
	names []byte
}

// Context returns the context object provided at load time.
func (d *Decoder) Context() context.Context {
	return d.ds.ctx
}

// uint reads a varint.
func (d *Decoder) uint() uint64 {
	return wire.ReadUint(d.r)
}

// BeginWait starts decoding a field loaded with Source.LoadWait, or saved
// through a value.
func (d *Decoder) BeginWait() {
	d.lastRef = 0
}

// EndWait finishes decoding a field loaded with Source.LoadWait.
func (d *Decoder) EndWait() {
	if d.lastRef != 0 {
		d.ds.wait(d.ods, d.lastRef, nil)
	}
}

// EndValue finishes decoding a field saved through a value, returning the
// object that the field's loader must wait for (see LoadValueNow).
func (d *Decoder) EndValue() uint32 {
	return uint32(d.lastRef)
}

// LoadValueNow returns true if the loader of a field saved through a value,
// whose decoding returned ref (see EndValue), can run now. Otherwise, the
// caller must call LoadValueLater.
func (d *Decoder) LoadValueNow(ref uint32) bool {
	id := objectID(ref)
	return id == 0 || id == d.ods.id || id == 1
}

// LoadValueLater calls x.StateLoadValue(ctx, field, v), to load the field
// saved through the value v, once the object ref is complete. See
// LoadValueNow.
func (d *Decoder) LoadValueLater(ref uint32, x valueLoader, field int, v any) {
	ds := d.ds
	if len(ds.valueCallbacks) == 0 {
		ds.valueCallbacks = make([]valueCallback, 32)
	}
	vc := &ds.valueCallbacks[0]
	ds.valueCallbacks = ds.valueCallbacks[1:]
	*vc = valueCallback{x: x, field: field, v: v}
	ds.waitCallback(d.ods, objectID(ref), callback{obj: vc})
}

// AfterLoad implements Source.AfterLoad for Codec structs with an afterLoad
// method, without allocating.
func (d *Decoder) AfterLoad(a afterLoader) {
	d.ods.addCallback(d.ds, callback{obj: a})
}

// LoadEncoded loads the next value as a wire.Object, for LoadValue.
func (d *Decoder) LoadEncoded() wire.Object {
	return wire.Load(d.r)
}

// LoadValue implements Source.LoadValue for a value loaded by LoadEncoded.
func (d *Decoder) LoadValue(encoded wire.Object, objPtr any, fn func(any)) {
	o := reflect.ValueOf(objPtr)
	d.ds.decodeObject(d.ods, o.Elem(), encoded)
	d.ds.waitObject(d.ods, encoded, func() { fn(o.Elem().Interface()) })
}

// refOf returns the object that waitObject waits for.
func refOf(encoded wire.Object) objectID {
	switch x := encoded.(type) {
	case *wire.Ref:
		return objectID(x.Root)
	case *wire.Slice:
		return objectID(x.Ref.Root)
	case *wire.Interface:
		return refOf(x.Value)
	}
	return 0
}

// legacy decodes a tagged wire.Object into obj using decodeObject.
func (d *Decoder) legacy(obj reflect.Value) {
	encoded := wire.Load(d.r)
	d.ds.decodeObject(d.ods, obj, encoded)
	d.lastRef = refOf(encoded)
}

// newObject creates the object with the given ID at ptr, of type typ, which
// will be decoded by dec.
func (ds *decodeState) newObject(id objectID, ptr unsafe.Pointer, typ reflect.Type, dec typedDecoder, decArg any) *objectDecodeState {
	ods := ds.addObject(id, reflect.NewAt(typ, ptr).Elem())
	ods.dec = dec
	ods.decArg = decArg
	// The object may have been written before this reference (see
	// writeObjects).
	if len(ds.deferred) != 0 {
		if encoded, ok := ds.deferred[id]; ok {
			delete(ds.deferred, id)
			ds.decodeObject(ods, ods.obj, encoded)
		}
	}
	ds.decodeStandalone(ods)
	return ods
}

// pointerArena is storage for pointer-shaped objects (see allocPointer).
type pointerArena []unsafe.Pointer

// allocPointer returns storage for a pointer-shaped object.
func (ds *decodeState) allocPointer() unsafe.Pointer {
	if len(ds.pointerArena) == 0 {
		ds.pointerArena = make(pointerArena, 64)
	}
	p := &ds.pointerArena[0]
	ds.pointerArena = ds.pointerArena[1:]
	return unsafe.Pointer(p)
}

// ref reads a reference: zero for nil, or an object ID shifted left by one,
// with the low bit set if dots and a type follow (see writeRef). If dots
// follow, the caller must call target.
func (d *Decoder) ref() (root objectID, dots bool) {
	v := d.uint()
	return objectID(v >> 1), v&1 != 0
}

// dot is a reference dot read by target.
type dot struct {
	// index is the array index, or the length of the field name in names,
	// for fields.
	index int
	field bool
}

// fieldKey identifies a struct field by name.
type fieldKey struct {
	typ  reflect.Type
	name string
}

// target reads the dots and type of a reference to a part of the object
// root (see ref), of type typ, and returns its address. Dots are walked by
// reflection, but without allocating.
func (d *Decoder) target(root objectID, typ reflect.Type) unsafe.Pointer {
	n := d.uint()
	if n > 1<<10 {
		Failf("invalid number of reference dots %d", n)
	}
	d.dots = d.dots[:0]
	d.names = d.names[:0]
	for i := uint64(0); i < n; i++ {
		x := wire.ReadInt(d.r)
		if x >= 0 {
			d.dots = append(d.dots, dot{index: int(x)})
			continue
		}
		l := -x
		if l > 1<<16 {
			Failf("invalid field name length %d", l)
		}
		start := len(d.names)
		d.names = append(d.names, make([]byte, l)...)
		wire.ReadFull(d.r, d.names[start:])
		d.dots = append(d.dots, dot{index: int(l), field: true})
	}
	spec := wire.ReadTypeSpec(d.r)
	ds := d.ds
	ds.growObjectsByID(root)
	ods := ds.objectsByID[root-1]
	if ods == nil {
		otyp := ds.findType(spec)
		ods = ds.newObject(root, reflect.New(otyp).UnsafePointer(), otyp, nil, nil)
	}
	// Dots are in reverse order; field names are in order in names.
	obj := ods.obj
	end := len(d.names)
	for i := len(d.dots) - 1; i >= 0; i-- {
		dt := d.dots[i]
		if !dt.field {
			if obj.Kind() != reflect.Array || dt.index >= obj.Len() {
				Failf("invalid reference index %d into %v", dt.index, obj.Type())
			}
			obj = obj.Index(dt.index)
			continue
		}
		if obj.Kind() != reflect.Struct {
			Failf("invalid reference field into %v", obj.Type())
		}
		name := d.names[end-dt.index : end]
		end -= dt.index
		key := fieldKey{obj.Type(), unsafe.String(unsafe.SliceData(name), len(name))}
		f, ok := ds.fields[key]
		if !ok {
			sf, found := key.typ.FieldByName(key.name)
			if !found || len(sf.Index) != 1 {
				Failf("no field %q in %v", key.name, key.typ)
			}
			f = sf.Index[0]
			key.name = string(name)
			if ds.fields == nil {
				ds.fields = make(map[fieldKey]int)
			}
			ds.fields[key] = f
		}
		obj = obj.Field(f)
	}
	if obj.Type() != typ {
		Failf("reference to %v, not %v", obj.Type(), typ)
	}
	return obj.Addr().UnsafePointer()
}

// structValue decodes a struct of type typ at p, implementing Codec c.
func (d *Decoder) structValue(p unsafe.Pointer, typ reflect.Type, c Codec) {
	ds := d.ds
	if ds.stats.enabled {
		// Types have no IDs in the typed format: use TypeIndex.
		index := c.StateTypeIndex().get()
		for int(index) >= len(ds.typedNames) {
			ds.typedNames = append(ds.typedNames, "")
		}
		ds.typedNames[index] = reverseTypeDatabase[typ].Name
		ds.stats.start(typeID(index))
		defer ds.stats.done()
	}
	c.StateDecode(ds.ctx, d)
	d.lastRef = 0
}

// decodeTop decodes the top-level object ods, in the typed format.
func (ds *decodeState) decodeTop(d *Decoder, ods *objectDecodeState) {
	d.ods = ods
	if ods.dec != nil {
		ods.dec.decode(d, ods)
		return
	}
	if ods.obj.Kind() == reflect.Struct {
		if c, ok := ods.obj.Addr().Interface().(Codec); ok {
			d.structValue(ods.ptr, ods.obj.Type(), c)
			return
		}
	}
	Failf("no typed decoder for object %d of type %v", ods.id, ods.obj.Type())
}

// loadStandalone reads the standalone object id (see writeObjects), whose
// state is ods if it was created already. Structs have their type, so they
// can be created here. If ods can't be decoded yet, decodeStandalone decodes
// it once it is created with its decoder, or gets it.
func (ds *decodeState) loadStandalone(id objectID, ods *objectDecodeState) {
	spec := wire.ReadTypeSpec(&ds.r)
	n := wire.ReadUint(&ds.r)
	if _, ok := spec.(wire.TypeSpecNil); ods == nil && !ok {
		typ := ds.findType(spec)
		ods = ds.newObject(id, reflect.New(typ).UnsafePointer(), typ, nil, nil)
	}
	if ods != nil && (ods.dec != nil || ods.obj.Kind() == reflect.Struct) {
		ds.decodeTop(&ds.dec, ods)
		return
	}
	if n > math.MaxInt32 {
		Failf("invalid object length %d", n)
	}
	b := make([]byte, n)
	wire.ReadFull(&ds.r, b)
	if ds.standalone == nil {
		ds.standalone = make(map[objectID][]byte)
	}
	ds.standalone[id] = b
}

// decodeStandalone decodes ods if it is a standalone object read already, and
// its decoder is known.
func (ds *decodeState) decodeStandalone(ods *objectDecodeState) {
	if len(ds.standalone) == 0 || (ods.dec == nil && ods.obj.Kind() != reflect.Struct) {
		return
	}
	b, ok := ds.standalone[ods.id]
	if !ok {
		return
	}
	delete(ds.standalone, ods.id)
	r := wire.Reader{Reader: bytes.NewReader(b)}
	ds.decodeTop(&Decoder{ds: ds, r: &r}, ods)
}

// setDecoder sets the decoder of ods, created by a reference that didn't
// provide it.
func (ds *decodeState) setDecoder(ods *objectDecodeState, dec typedDecoder, decArg any) {
	ods.dec, ods.decArg = dec, decArg
	ds.decodeStandalone(ods)
}

// DecodeBool decodes a bool.
func DecodeBool[T ~bool](d *Decoder, p *T) {
	if d.uint() != 0 {
		*p = true
	}
}

// DecodeInt decodes a signed integer.
func DecodeInt[T Signed](d *Decoder, p *T) {
	if v := wire.ReadInt(d.r); v != 0 {
		*p = T(v)
		if int64(*p) != v {
			Failf("signed integer truncated from %v to %v", v, int64(*p))
		}
	}
}

// DecodeUint decodes an unsigned integer.
func DecodeUint[T Unsigned](d *Decoder, p *T) {
	if v := d.uint(); v != 0 {
		*p = T(v)
		if uint64(*p) != v {
			Failf("unsigned integer truncated from %v to %v", v, uint64(*p))
		}
	}
}

// fixed reads n bytes, without copying them if possible. The returned bytes
// are valid until the next read.
func (d *Decoder) fixed(n int) []byte {
	return wire.ReadFixed(d.r, n)
}

// DecodeFloat32 decodes a float32.
func DecodeFloat32[T ~float32](d *Decoder, p *T) {
	if v := binary.LittleEndian.Uint32(d.fixed(4)); v != 0 {
		*p = T(math.Float32frombits(v))
	}
}

// DecodeFloat64 decodes a float64.
func DecodeFloat64[T ~float64](d *Decoder, p *T) {
	if v := binary.LittleEndian.Uint64(d.fixed(8)); v != 0 {
		*p = T(math.Float64frombits(v))
	}
}

// DecodeComplex64 decodes a complex64.
func DecodeComplex64[T ~complex64](d *Decoder, p *T) {
	b := d.fixed(8)
	re, im := binary.LittleEndian.Uint32(b), binary.LittleEndian.Uint32(b[4:])
	if re != 0 || im != 0 {
		*p = T(complex(math.Float32frombits(re), math.Float32frombits(im)))
	}
}

// DecodeComplex128 decodes a complex128.
func DecodeComplex128[T ~complex128](d *Decoder, p *T) {
	b := d.fixed(16)
	re, im := binary.LittleEndian.Uint64(b), binary.LittleEndian.Uint64(b[8:])
	if re != 0 || im != 0 {
		*p = T(complex(math.Float64frombits(re), math.Float64frombits(im)))
	}
}

// string_ reads a string.
func (d *Decoder) string_() string {
	n := d.uint()
	if n == 0 {
		return ""
	}
	if n > math.MaxInt32 {
		Failf("invalid string length %d", n)
	}
	b := make([]byte, n)
	wire.ReadFull(d.r, b)
	return unsafe.String(&b[0], len(b))
}

// DecodeString decodes a string.
func DecodeString[T ~string](d *Decoder, p *T) {
	if s := d.string_(); s != "" {
		*p = T(s)
	}
}

// DecodePointer decodes a pointer.
func DecodePointer[P ~*T, T any](d *Decoder, p *P) {
	d.pointer(unsafe.Pointer(p), typeOf[T]())
}

// pointer decodes a pointer to an object of type typ into the pointer at p.
func (d *Decoder) pointer(p unsafe.Pointer, typ reflect.Type) {
	root, dots := d.ref()
	d.lastRef = root
	if root == 0 {
		return
	}
	if dots {
		*(*unsafe.Pointer)(p) = d.target(root, typ)
		return
	}
	if ods := d.ds.lookup(root); ods != nil {
		if ods.obj.Type() != typ {
			Failf("object %d has type %v, not %v", root, ods.obj.Type(), typ)
		}
		*(*unsafe.Pointer)(p) = ods.ptr
		return
	}
	*(*unsafe.Pointer)(p) = d.ds.newObject(root, reflect.New(typ).UnsafePointer(), typ, nil, nil).ptr
}

// sliceDecoder decodes arrays backing []T slices.
type sliceDecoder[T any] struct {
	elem func(*Decoder, *T)
}

// decode implements typedDecoder.decode.
func (s sliceDecoder[T]) decode(d *Decoder, ods *objectDecodeState) {
	DecodeArray(d, unsafe.Slice((*T)(ods.ptr), ods.obj.Len()), s.elem)
}

// alloc implements arrayDecoder.alloc.
func (sliceDecoder[T]) alloc(n int) unsafe.Pointer {
	return unsafe.Pointer(unsafe.SliceData(make([]T, n)))
}

// DecodeSlice decodes a slice whose elements are decoded by elem.
func DecodeSlice[S ~[]T, T any](d *Decoder, p *S, elem func(*Decoder, *T)) {
	ptr, length, capacity, ok := d.slice(typeOf[T](), sliceDecoder[T]{elem})
	if ok {
		*p = S(unsafe.Slice((*T)(ptr), capacity)[:length:capacity])
	}
}

// slice decodes a slice of elements of type elemTyp (see Encoder.slice). If
// the slice is not nil, it returns its backing array, allocated by alloc and
// decoded by dec if needed, with its length and capacity.
func (d *Decoder) slice(elemTyp reflect.Type, dec arrayDecoder) (unsafe.Pointer, int, int, bool) {
	capacity := d.uint()
	if capacity == 0 {
		d.lastRef = 0
		return nil, 0, 0, false
	}
	capacity--
	length := d.uint()
	root, dots := d.ref()
	d.lastRef = root
	if length > capacity || capacity > math.MaxInt32 || root == 0 {
		Failf("invalid slice length %d, capacity %d, object %d", length, capacity, root)
	}
	var ods *objectDecodeState
	if dots {
		return d.target(root, reflect.ArrayOf(int(capacity), elemTyp)), int(length), int(capacity), true
	} else if ods = d.ds.lookup(root); ods != nil {
		if ods.obj.Kind() != reflect.Array || ods.obj.Type().Elem() != elemTyp || uint64(ods.obj.Len()) < capacity {
			Failf("object %d has type %v, not [%d]%v", root, ods.obj.Type(), capacity, elemTyp)
		}
		if ods.dec == nil {
			// Created by decodeObject or a reference into the
			// object, which didn't provide its decoder.
			d.ds.setDecoder(ods, dec, nil)
		}
	} else {
		ods = d.ds.newObject(root, dec.alloc(int(capacity)), reflect.ArrayOf(int(capacity), elemTyp), dec, nil)
	}
	return ods.ptr, int(length), int(capacity), true
}

// byteArray decodes an array of n elements of kind uint8 at p.
func (d *Decoder) byteArray(p unsafe.Pointer, n int) {
	if n > 0 {
		wire.ReadFull(d.r, unsafe.Slice((*byte)(p), n))
	}
}

// byteSliceDecoder decodes arrays backing slices of elements of kind uint8.
type byteSliceDecoder struct{}

// decode implements typedDecoder.decode.
func (byteSliceDecoder) decode(d *Decoder, ods *objectDecodeState) {
	d.byteArray(ods.ptr, ods.obj.Len())
}

// alloc implements arrayDecoder.alloc.
func (byteSliceDecoder) alloc(n int) unsafe.Pointer {
	return unsafe.Pointer(unsafe.SliceData(make([]byte, n)))
}

// byteSlice decodes a slice of elements of kind uint8 into p, of type typ.
func (d *Decoder) byteSlice(p unsafe.Pointer, typ reflect.Type) {
	if ptr, length, capacity, ok := d.slice(typ.Elem(), byteSliceDecoder{}); ok {
		*(*[]byte)(p) = unsafe.Slice((*byte)(ptr), capacity)[:length:capacity]
	}
}

// DecodeArray decodes an array (passed as a slice of the whole array) whose
// elements are decoded by elem.
func DecodeArray[T any](d *Decoder, a []T, elem func(*Decoder, *T)) {
	if len(a) == 0 {
		return
	}
	if typeOf[T]().Kind() == reflect.Uint8 {
		d.byteArray(unsafe.Pointer(&a[0]), len(a))
		d.lastRef = 0
		return
	}
	ds, ods := d.ds, d.ods
	for i := range a {
		d.lastRef = 0
		elem(d, &a[i])
		if d.lastRef != 0 {
			ds.wait(ods, d.lastRef, nil)
		}
	}
	d.lastRef = 0
}

// mapDecoder decodes maps, with key; the value decoder is in decArg.
type mapDecoder[M ~map[K]V, K comparable, V any] struct {
	key func(*Decoder, *K)
}

// decode implements typedDecoder.decode.
func (md mapDecoder[M, K, V]) decode(d *Decoder, ods *objectDecodeState) {
	val := ods.decArg.(func(*Decoder, *V))
	m := *(*M)(ods.ptr)
	n := d.uint()
	ds := d.ds
	// Struct and array loaders may retain the addresses of the keys and
	// values (for afterLoad), so these must be distinct; other values are
	// copied into the map, and their variables can be reused.
	reuseKey := typeOf[K]().Kind() != reflect.Struct && typeOf[K]().Kind() != reflect.Array
	reuseVal := typeOf[V]().Kind() != reflect.Struct && typeOf[V]().Kind() != reflect.Array
	var k *K
	var v *V
	if reuseKey && reuseVal {
		// Reuse variables across maps of the same type, as mapEncoder.
		kv, _ := ds.mapScratch[ods.obj.Type()].(*mapEntry[K, V])
		if kv == nil {
			kv = new(mapEntry[K, V])
			if ds.mapScratch == nil {
				ds.mapScratch = make(map[reflect.Type]any)
			}
			ds.mapScratch[ods.obj.Type()] = kv
		}
		k, v = &kv.k, &kv.v
		*kv = mapEntry[K, V]{}
	} else {
		k, v = new(K), new(V)
	}
	for i := uint64(0); i < n; i++ {
		if i > 0 {
			if reuseKey {
				*k = *new(K)
			} else {
				k = new(K)
			}
			if reuseVal {
				*v = *new(V)
			} else {
				v = new(V)
			}
		}
		d.lastRef = 0
		md.key(d, k)
		kRef := d.lastRef
		d.lastRef = 0
		val(d, v)
		vRef := d.lastRef
		if kRef != 0 {
			ds.wait(ods, kRef, nil)
		}
		if vRef != 0 {
			ds.wait(ods, vRef, nil)
		}
		m[*k] = *v
	}
	d.lastRef = 0
}

// DecodeMap decodes a map whose keys and values are decoded by key and val.
func DecodeMap[M ~map[K]V, K comparable, V any](d *Decoder, p *M, key func(*Decoder, *K), val func(*Decoder, *V)) {
	root, dots := d.ref()
	d.lastRef = root
	if root == 0 {
		return
	}
	if dots {
		Failf("reference into map object %d", root)
	}
	if ods := d.ds.lookup(root); ods != nil {
		if ods.obj.Type() != typeOf[M]() {
			Failf("object %d has type %v, not %v", root, ods.obj.Type(), typeOf[M]())
		}
		mp := (*M)(ods.ptr)
		if *mp == nil {
			*mp = make(M)
		}
		if ods.dec == nil {
			// See Decoder.slice.
			d.ds.setDecoder(ods, mapDecoder[M, K, V]{key}, val)
		}
		*p = *mp
		return
	}
	// Maps are pointer-shaped.
	mp := (*M)(d.ds.allocPointer())
	*mp = make(M)
	d.ds.newObject(root, unsafe.Pointer(mp), typeOf[M](), mapDecoder[M, K, V]{key}, val)
	*p = *mp
}

// localType returns the local type for the given type ID.
func (ds *decodeState) localType(id typeID) reflect.Type {
	if int(id) <= len(ds.types.byID) {
		if rte := ds.types.byID[id-1]; rte != nil {
			return rte.LocalType
		}
	}
	return ds.findType(wire.TypeID(id))
}

// iface decodes an interface value (see Encoder.iface) into the interface of
// type typ at p. If the value is decoded without decodeObject, it is
// returned with set == true, to be assigned by the caller.
func (d *Decoder) iface(p unsafe.Pointer, typ reflect.Type) (v any, set bool) {
	code := d.uint()
	if code == 0 {
		d.lastRef = 0
		return nil, false
	}
	kind := code & 3
	if kind == ifaceLegacy {
		d.legacy(reflect.NewAt(typ, p).Elem())
		return nil, false
	}
	elemTyp := d.ds.localType(typeID(code >> 2))
	if kind == ifaceNilPointer {
		d.lastRef = 0
		return reflect.Zero(reflect.PointerTo(elemTyp)).Interface(), true
	}
	var ptr unsafe.Pointer
	d.pointer(unsafe.Pointer(&ptr), elemTyp)
	return reflect.NewAt(elemTyp, ptr).Interface(), true
}

// DecodeInterface decodes an interface.
func DecodeInterface[T any](d *Decoder, p *T) {
	// Assign through a type assertion, which caches the interface table,
	// rather than with reflect.Value.Set, which checks the method sets.
	if v, set := d.iface(unsafe.Pointer(p), typeOf[T]()); set {
		*p = v.(T)
	}
}

// DecodeValue decodes a value of any type. It is used for elements whose kind
// is not known to go_stateify.
func DecodeValue[T any](d *Decoder, p *T) {
	if v, set := d.value(unsafe.Pointer(p), typeOf[T](), any(p)); set {
		*p = v.(T)
	}
}

// DecodeAny is DecodeValue for p of type *T, without instantiating code for
// each type T. It is used for fields whose kind is not known to go_stateify.
func DecodeAny(d *Decoder, p any) {
	rv := reflect.ValueOf(p)
	if v, set := d.value(rv.UnsafePointer(), rv.Type().Elem(), p); set {
		rv.Elem().Set(reflect.ValueOf(v))
	}
}

// value implements DecodeValue for the value of type typ at up. pi is a
// pointer to it. If typ is an interface type, the decoded value may be
// returned with set == true, to be assigned by the caller.
func (d *Decoder) value(up unsafe.Pointer, typ reflect.Type, pi any) (v any, set bool) {
	if c, ok := pi.(Codec); ok && typ.Kind() == reflect.Struct {
		d.structValue(up, typ, c)
		return nil, false
	}
	switch typ.Kind() {
	case reflect.Bool:
		DecodeBool(d, (*bool)(up))
	case reflect.Int:
		DecodeInt(d, (*int)(up))
	case reflect.Int8:
		DecodeInt(d, (*int8)(up))
	case reflect.Int16:
		DecodeInt(d, (*int16)(up))
	case reflect.Int32:
		DecodeInt(d, (*int32)(up))
	case reflect.Int64:
		DecodeInt(d, (*int64)(up))
	case reflect.Uint:
		DecodeUint(d, (*uint)(up))
	case reflect.Uint8:
		DecodeUint(d, (*uint8)(up))
	case reflect.Uint16:
		DecodeUint(d, (*uint16)(up))
	case reflect.Uint32:
		DecodeUint(d, (*uint32)(up))
	case reflect.Uint64:
		DecodeUint(d, (*uint64)(up))
	case reflect.Uintptr:
		DecodeUint(d, (*uintptr)(up))
	case reflect.Float32:
		DecodeFloat32(d, (*float32)(up))
	case reflect.Float64:
		DecodeFloat64(d, (*float64)(up))
	case reflect.Complex64:
		DecodeComplex64(d, (*complex64)(up))
	case reflect.Complex128:
		DecodeComplex128(d, (*complex128)(up))
	case reflect.String:
		DecodeString(d, (*string)(up))
	case reflect.Ptr:
		d.pointer(up, typ.Elem())
	case reflect.Interface:
		return d.iface(up, typ)
	case reflect.Slice:
		if typ.Elem().Kind() != reflect.Uint8 {
			d.legacy(reflect.NewAt(typ, up).Elem())
			break
		}
		d.byteSlice(up, typ)
	case reflect.Array:
		if typ.Elem().Kind() != reflect.Uint8 {
			d.legacy(reflect.NewAt(typ, up).Elem())
			break
		}
		d.byteArray(up, typ.Len())
		d.lastRef = 0
	case reflect.Struct:
		if typ.NumField() != 0 {
			d.legacy(reflect.NewAt(typ, up).Elem())
			break
		}
		// Structs without fields are not encoded.
		d.lastRef = 0
	default:
		d.legacy(reflect.NewAt(typ, up).Elem())
	}
	return nil, false
}
