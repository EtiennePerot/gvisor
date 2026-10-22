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

// Tag is the tag of a serialized value. See wire.Tag.
type Tag = wire.Tag

// Decoder decodes values directly from their serialized form. It is used by
// generated StateDecode methods.
//
// Decoding has the same semantics as decodeObject: for example, Nil leaves
// the destination unchanged, and integers that do not fit their destination
// are errors. Values that the typed functions don't handle are loaded as
// wire.Objects and decoded by decodeObject.
type Decoder struct {
	ds *decodeState

	// ods is the object being decoded.
	ods *objectDecodeState

	// r is the input stream.
	r *wire.Reader

	// pendingTag, if hasPendingTag, is the tag of the next value, which has
	// already been read.
	pendingTag    Tag
	hasPendingTag bool

	// lastRef is the object referred to by the last decoded value, as found
	// by waitObject, or zero.
	lastRef objectID
}

// Context returns the context object provided at load time.
func (d *Decoder) Context() context.Context {
	return d.ds.ctx
}

// Tag reads the tag of the next value.
func (d *Decoder) Tag() Tag {
	if d.hasPendingTag {
		d.hasPendingTag = false
		return d.pendingTag
	}
	return wire.Tag(wire.ReadUint(d.r))
}

// uint reads a Uint.
func (d *Decoder) uint() uint64 {
	return wire.ReadUint(d.r)
}

// BeginWait starts decoding a field loaded with Source.LoadWait.
func (d *Decoder) BeginWait() {
	d.lastRef = 0
}

// EndWait finishes decoding a field loaded with Source.LoadWait.
func (d *Decoder) EndWait() {
	if d.lastRef != 0 {
		d.ds.wait(d.ods, d.lastRef, nil)
	}
}

// AfterLoad implements Source.AfterLoad.
func (d *Decoder) AfterLoad(fn func()) {
	d.ods.addCallback(userCallback(fn))
}

// LoadEncoded loads the next value as a wire.Object, for LoadValue.
func (d *Decoder) LoadEncoded() wire.Object {
	return wire.LoadTagged(d.r, d.Tag())
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

// fallback decodes a value with tag tag into obj using decodeObject.
func (d *Decoder) fallback(obj reflect.Value, tag Tag) {
	encoded := wire.LoadTagged(d.r, tag)
	d.ds.decodeObject(d.ods, obj, encoded)
	d.lastRef = refOf(encoded)
}

// fallbackAt is fallback for the value of type T at p.
func fallbackAt[T any](d *Decoder, p *T, tag Tag) {
	d.fallback(reflect.NewAt(typeOf[T](), unsafe.Pointer(p)).Elem(), tag)
}

// newObject creates the object with the given ID at ptr, of type typ, which
// will be decoded by dec.
func (ds *decodeState) newObject(id objectID, ptr unsafe.Pointer, typ reflect.Type, dec objectDecodeFunc, decArg any) *objectDecodeState {
	ods := ds.addObject(id, reflect.NewAt(typ, ptr).Elem())
	ods.dec = dec
	ods.decArg = decArg
	if encoded, ok := ds.deferred[id]; ok {
		delete(ds.deferred, id)
		ds.decodeObject(ods, ods.obj, encoded)
	}
	return ods
}

// readRef reads the contents of a Ref. It returns a non-nil *wire.Ref if the
// reference has dots.
func (d *Decoder) readRef() (objectID, *wire.Ref) {
	root := objectID(d.uint())
	ndots := d.uint()
	if ndots == 0 {
		return root, nil
	}
	ref := &wire.Ref{Root: wire.Uint(root), Dots: wire.ReadDots(d.r, ndots)}
	ref.Type = wire.ReadTypeSpec(d.r)
	return root, ref
}

// target returns the address of the object of type typ referred to by ref.
func (d *Decoder) target(ref *wire.Ref, typ reflect.Type) unsafe.Pointer {
	return d.ds.register(ref, typ).Addr().UnsafePointer()
}

// structValue decodes a struct of type typ at p, implementing Codec c.
func (d *Decoder) structValue(p unsafe.Pointer, typ reflect.Type, c Codec, tag Tag) {
	if tag != wire.TagStruct {
		d.fallback(reflect.NewAt(typ, p).Elem(), tag)
		return
	}
	ds := d.ds
	id := typeID(d.uint())
	if id == 0 {
		d.ds.decodeStruct(d.ods, reflect.NewAt(typ, p).Elem(), wire.LoadStructFields(d.r, 0))
		d.lastRef = 0
		return
	}
	rte := ds.types.Lookup(id, typ)
	if !rte.identity {
		ds.decodeStruct(d.ods, reflect.NewAt(typ, p).Elem(), wire.LoadStructFields(d.r, wire.TypeID(id)))
		d.lastRef = 0
		return
	}
	ft := wire.Tag(d.uint())
	switch n := len(rte.Fields); n {
	case 0:
		if ft != wire.TagNoObjects {
			Failf("type %q has no fields, got %d", rte.Name, ft)
		}
	case 1:
		d.pendingTag, d.hasPendingTag = ft, true
	default:
		if ft != wire.TagMultipleObjects {
			Failf("type %q has %d fields, got %d", rte.Name, n, ft)
		}
		if count := d.uint(); count != uint64(n) {
			Failf("type %q has %d fields, got %d", rte.Name, n, count)
		}
	}
	d.ods.typ = id
	if ds.stats.enabled {
		ds.stats.start(id)
		defer ds.stats.done()
	}
	c.StateDecode(ds.ctx, d)
	if d.hasPendingTag {
		Failf("type %q: field not decoded", rte.Name)
	}
	d.lastRef = 0
}

// decodeTop decodes the top-level object ods, whose tag has been read. It
// returns false if ods must be decoded by decodeObject.
func (ds *decodeState) decodeTop(ods *objectDecodeState, tag Tag) bool {
	d := &ds.dec
	if ods.dec != nil {
		d.ods = ods
		ods.dec(d, ods, tag)
		return true
	}
	if ods.obj.Kind() != reflect.Struct {
		return false
	}
	c, ok := ods.obj.Addr().Interface().(Codec)
	if !ok {
		return false
	}
	d.ods = ods
	d.structValue(ods.ptr, ods.obj.Type(), c, tag)
	return true
}

// DecodeBool decodes a bool.
func DecodeBool[T ~bool](d *Decoder, p *T, tag Tag) {
	switch tag {
	case wire.TagNil:
	case wire.TagBool:
		*p = d.uint() == 1
	default:
		fallbackAt(d, p, tag)
	}
}

// DecodeInt decodes a signed integer.
func DecodeInt[T Signed](d *Decoder, p *T, tag Tag) {
	switch tag {
	case wire.TagNil:
	case wire.TagInt:
		v := wire.ReadInt(d.r)
		*p = T(v)
		if int64(*p) != v {
			Failf("signed integer truncated from %v to %v", v, int64(*p))
		}
	default:
		fallbackAt(d, p, tag)
	}
}

// DecodeUint decodes an unsigned integer.
func DecodeUint[T Unsigned](d *Decoder, p *T, tag Tag) {
	switch tag {
	case wire.TagNil:
	case wire.TagUint:
		v := d.uint()
		*p = T(v)
		if uint64(*p) != v {
			Failf("unsigned integer truncated from %v to %v", v, uint64(*p))
		}
	default:
		fallbackAt(d, p, tag)
	}
}

// DecodeFloat32 decodes a float32.
func DecodeFloat32[T ~float32](d *Decoder, p *T, tag Tag) {
	switch tag {
	case wire.TagNil:
	case wire.TagFloat32:
		*p = T(wire.ReadFloat32(d.r))
	default:
		fallbackAt(d, p, tag)
	}
}

// DecodeFloat64 decodes a float64.
func DecodeFloat64[T ~float64](d *Decoder, p *T, tag Tag) {
	switch tag {
	case wire.TagNil:
	case wire.TagFloat64:
		*p = T(wire.ReadFloat64(d.r))
	default:
		fallbackAt(d, p, tag)
	}
}

// DecodeComplex64 decodes a complex64.
func DecodeComplex64[T ~complex64](d *Decoder, p *T, tag Tag) {
	switch tag {
	case wire.TagNil:
	case wire.TagComplex64:
		re := wire.ReadFloat32(d.r)
		im := wire.ReadFloat32(d.r)
		*p = T(complex(re, im))
	default:
		fallbackAt(d, p, tag)
	}
}

// DecodeComplex128 decodes a complex128.
func DecodeComplex128[T ~complex128](d *Decoder, p *T, tag Tag) {
	switch tag {
	case wire.TagNil:
	case wire.TagComplex128:
		re := wire.ReadFloat64(d.r)
		im := wire.ReadFloat64(d.r)
		*p = T(complex(re, im))
	default:
		fallbackAt(d, p, tag)
	}
}

// DecodeString decodes a string.
func DecodeString[T ~string](d *Decoder, p *T, tag Tag) {
	switch tag {
	case wire.TagNil:
	case wire.TagString:
		*p = T(wire.ReadString(d.r))
	default:
		fallbackAt(d, p, tag)
	}
}

// DecodePointer decodes a pointer.
func DecodePointer[P ~*T, T any](d *Decoder, p *P, tag Tag) {
	d.pointer(unsafe.Pointer(p), typeOf[T](), tag)
}

// pointer decodes a pointer to an object of type typ into the pointer at p.
func (d *Decoder) pointer(p unsafe.Pointer, typ reflect.Type, tag Tag) {
	switch tag {
	case wire.TagNil:
		return
	case wire.TagRef:
	default:
		d.fallback(reflect.NewAt(reflect.PointerTo(typ), p).Elem(), tag)
		return
	}
	root, ref := d.readRef()
	d.lastRef = root
	if root == 0 {
		return
	}
	if ref != nil {
		*(*unsafe.Pointer)(p) = d.target(ref, typ)
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

// decodeArrayObject is an objectDecodeFunc for arrays backing []T slices.
func decodeArrayObject[T any](d *Decoder, ods *objectDecodeState, tag Tag) {
	elem := ods.decArg.(func(*Decoder, *T, Tag))
	DecodeArray(d, unsafe.Slice((*T)(ods.ptr), ods.obj.Len()), tag, elem)
}

// DecodeSlice decodes a slice whose elements are decoded by elem.
func DecodeSlice[S ~[]T, T any](d *Decoder, p *S, tag Tag, elem func(*Decoder, *T, Tag)) {
	switch tag {
	case wire.TagNil:
		return
	case wire.TagSlice:
	default:
		fallbackAt(d, p, tag)
		return
	}
	ptr, length, capacity, ok := d.slice(typeOf[T](), allocArray[T], decodeArrayObject[T], elem)
	if ok {
		*p = S(unsafe.Slice((*T)(ptr), capacity)[:length:capacity])
	}
}

// slice decodes a slice of elements of type elemTyp, whose tag has been read.
// If the slice is not nil, it returns its backing array, allocated by alloc
// and decoded by dec if needed, with its length and capacity.
func (d *Decoder) slice(elemTyp reflect.Type, alloc func(int) unsafe.Pointer, dec objectDecodeFunc, decArg any) (unsafe.Pointer, int, int, bool) {
	length, capacity := d.uint(), d.uint()
	root, ref := d.readRef()
	d.lastRef = root
	if root == 0 {
		return nil, 0, 0, false
	}
	if length > capacity || capacity > math.MaxInt32 {
		Failf("invalid slice length %d, capacity %d", length, capacity)
	}
	var ptr unsafe.Pointer
	if ref != nil {
		ptr = d.target(ref, reflect.ArrayOf(int(capacity), elemTyp))
	} else if ods := d.ds.lookup(root); ods != nil {
		if ods.obj.Kind() != reflect.Array || ods.obj.Type().Elem() != elemTyp || uint64(ods.obj.Len()) < capacity {
			Failf("object %d has type %v, not [%d]%v", root, ods.obj.Type(), capacity, elemTyp)
		}
		ptr = ods.ptr
	} else {
		ptr = alloc(int(capacity))
		d.ds.newObject(root, ptr, reflect.ArrayOf(int(capacity), elemTyp), dec, decArg)
	}
	return ptr, int(length), int(capacity), true
}

// byteArray decodes an array of n elements of kind uint8 at p.
func (d *Decoder) byteArray(p unsafe.Pointer, n int, tag Tag) {
	DecodeArray(d, unsafe.Slice((*uint8)(p), n), tag, DecodeUint[uint8])
}

// decodeByteArrayObject is an objectDecodeFunc for arrays backing slices of
// elements of kind uint8.
func decodeByteArrayObject(d *Decoder, ods *objectDecodeState, tag Tag) {
	d.byteArray(ods.ptr, ods.obj.Len(), tag)
}

// allocArray allocates an array of n elements of type T.
func allocArray[T any](n int) unsafe.Pointer {
	return unsafe.Pointer(unsafe.SliceData(make([]T, n)))
}

// byteSlice decodes a slice of elements of kind uint8 into p, of type typ.
func (d *Decoder) byteSlice(p unsafe.Pointer, typ reflect.Type, tag Tag) {
	switch tag {
	case wire.TagNil:
		return
	case wire.TagSlice:
	default:
		d.fallback(reflect.NewAt(typ, p).Elem(), tag)
		return
	}
	if ptr, length, capacity, ok := d.slice(typ.Elem(), allocArray[byte], decodeByteArrayObject, nil); ok {
		*(*[]byte)(p) = unsafe.Slice((*byte)(ptr), capacity)[:length:capacity]
	}
}

// emptyStruct decodes a struct without fields, of type typ at p.
func (d *Decoder) emptyStruct(p unsafe.Pointer, typ reflect.Type, tag Tag) {
	if tag != wire.TagStruct {
		d.fallback(reflect.NewAt(typ, p).Elem(), tag)
		return
	}
	if id := d.uint(); id != 0 {
		// A registered type.
		d.ds.decodeStruct(d.ods, reflect.NewAt(typ, p).Elem(), wire.LoadStructFields(d.r, wire.TypeID(id)))
		d.lastRef = 0
		return
	}
	if ft := wire.Tag(d.uint()); ft != wire.TagNoObjects {
		Failf("empty struct %v has fields (tag %d)", typ, ft)
	}
	d.lastRef = 0
}

// DecodeArray decodes an array (passed as a slice of the whole array) whose
// elements are decoded by elem.
func DecodeArray[T any](d *Decoder, a []T, tag Tag, elem func(*Decoder, *T, Tag)) {
	switch tag {
	case wire.TagNil:
		return
	case wire.TagArray:
	default:
		Failf("array of %v has tag %d", typeOf[T](), tag)
	}
	if n := d.uint(); n != uint64(len(a)) {
		Failf("mismatching array length expect=%d, actual=%d", len(a), n)
	}
	if len(a) == 0 {
		return
	}
	et := d.Tag()
	ds, ods := d.ds, d.ods
	for i := range a {
		d.lastRef = 0
		elem(d, &a[i], et)
		if d.lastRef != 0 {
			ds.wait(ods, d.lastRef, nil)
		}
	}
	d.lastRef = 0
}

// mapDecoder holds what is needed to decode a map object.
type mapDecoder[K comparable, V any] struct {
	key func(*Decoder, *K, Tag)
	val func(*Decoder, *V, Tag)
}

// decodeMapObject is an objectDecodeFunc for maps.
func decodeMapObject[K comparable, V any](d *Decoder, ods *objectDecodeState, tag Tag) {
	md := ods.decArg.(*mapDecoder[K, V])
	m := *(*map[K]V)(ods.ptr)
	if tag != wire.TagMap {
		d.fallback(ods.obj, tag)
		return
	}
	n := d.uint()
	var kt, vt Tag
	ds := d.ds
	for i := uint64(0); i < n; i++ {
		var (
			k K
			v V
		)
		if i == 0 {
			kt = d.Tag()
		}
		d.lastRef = 0
		md.key(d, &k, kt)
		kRef := d.lastRef
		if i == 0 {
			vt = d.Tag()
		}
		d.lastRef = 0
		md.val(d, &v, vt)
		vRef := d.lastRef
		if kRef != 0 {
			ds.wait(ods, kRef, nil)
		}
		if vRef != 0 {
			ds.wait(ods, vRef, nil)
		}
		m[k] = v
	}
	d.lastRef = 0
}

// DecodeMap decodes a map whose keys and values are decoded by key and val.
func DecodeMap[M ~map[K]V, K comparable, V any](d *Decoder, p *M, tag Tag, key func(*Decoder, *K, Tag), val func(*Decoder, *V, Tag)) {
	switch tag {
	case wire.TagNil:
		return
	case wire.TagRef:
	default:
		fallbackAt(d, p, tag)
		return
	}
	root, ref := d.readRef()
	d.lastRef = root
	if root == 0 {
		return
	}
	if ref != nil {
		d.ds.decodeObject(d.ods, reflect.ValueOf(p).Elem(), ref)
		return
	}
	if ods := d.ds.lookup(root); ods != nil {
		if ods.obj.Type() != typeOf[M]() {
			Failf("object %d has type %v, not %v", root, ods.obj.Type(), typeOf[M]())
		}
		mp := (*M)(ods.ptr)
		if *mp == nil {
			*mp = make(M)
		}
		*p = *mp
		return
	}
	mp := new(M)
	*mp = make(M)
	d.ds.newObject(root, unsafe.Pointer(mp), typeOf[M](), decodeMapObject[K, V], &mapDecoder[K, V]{key, val})
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

// iface decodes an interface value into obj, of type typ at p. If the value
// is decoded without decodeObject, it is returned with set == true.
func (d *Decoder) iface(p unsafe.Pointer, typ reflect.Type, tag Tag) (v any, set bool) {
	switch tag {
	case wire.TagNil:
		return nil, false
	case wire.TagInterface:
	default:
		d.fallback(reflect.NewAt(typ, p).Elem(), tag)
		return nil, false
	}
	hdr := wire.Uint(d.uint())
	var ts wire.TypeSpec
	if hdr == wire.TypeSpecTagPointer {
		hdr2 := wire.Uint(d.uint())
		if hdr2 == wire.TypeSpecTagID {
			elemTyp := d.ds.localType(typeID(d.uint()))
			vt := d.Tag()
			if vt != wire.TagRef {
				// Not possible for a pointer.
				Failf("interface pointer value has tag %d", vt)
			}
			root, ref := d.readRef()
			d.lastRef = root
			if root == 0 {
				return reflect.Zero(reflect.PointerTo(elemTyp)).Interface(), true
			}
			var ptr unsafe.Pointer
			if ref != nil {
				ptr = d.target(ref, elemTyp)
			} else if ods := d.ds.lookup(root); ods != nil {
				if ods.obj.Type() != elemTyp {
					Failf("object %d has type %v, not %v", root, ods.obj.Type(), elemTyp)
				}
				ptr = ods.ptr
			} else {
				ptr = d.ds.newObject(root, reflect.New(elemTyp).UnsafePointer(), elemTyp, nil, nil).ptr
			}
			return reflect.NewAt(elemTyp, ptr).Interface(), true
		}
		ts = &wire.TypeSpecPointer{Type: wire.ReadTypeSpecBody(d.r, hdr2)}
	} else {
		ts = wire.ReadTypeSpecBody(d.r, hdr)
	}
	encoded := &wire.Interface{Type: ts, Value: wire.Load(d.r)}
	d.ds.decodeObject(d.ods, reflect.NewAt(typ, p).Elem(), encoded)
	d.lastRef = refOf(encoded)
	return nil, false
}

// DecodeInterface decodes an interface.
func DecodeInterface[T any](d *Decoder, p *T, tag Tag) {
	// Assign through a type assertion, which caches the interface table,
	// rather than with reflect.Value.Set, which checks the method sets.
	if v, set := d.iface(unsafe.Pointer(p), typeOf[T](), tag); set {
		*p = v.(T)
	}
}

// DecodeValue decodes a value of any type. It is used for types whose kind is
// not known to go_stateify, and by the other Decode functions.
func DecodeValue[T any](d *Decoder, p *T, tag Tag) {
	if v, set := d.value(unsafe.Pointer(p), typeOf[T](), any(p), tag); set {
		*p = v.(T)
	}
}

// DecodeAny is DecodeValue for p of type *T, without instantiating code for
// each type T. It is used for fields whose kind is not known to go_stateify.
func DecodeAny(d *Decoder, p any, tag Tag) {
	rv := reflect.ValueOf(p)
	if v, set := d.value(rv.UnsafePointer(), rv.Type().Elem(), p, tag); set {
		rv.Elem().Set(reflect.ValueOf(v))
	}
}

// value implements DecodeValue for the value of type typ at up. pi is a
// pointer to it. If typ is an interface type, the decoded value may be
// returned with set == true, to be assigned by the caller.
func (d *Decoder) value(up unsafe.Pointer, typ reflect.Type, pi any, tag Tag) (v any, set bool) {
	if c, ok := pi.(Codec); ok && typ.Kind() == reflect.Struct {
		d.structValue(up, typ, c, tag)
		return nil, false
	}
	switch typ.Kind() {
	case reflect.Bool:
		DecodeBool(d, (*bool)(up), tag)
	case reflect.Int:
		DecodeInt(d, (*int)(up), tag)
	case reflect.Int8:
		DecodeInt(d, (*int8)(up), tag)
	case reflect.Int16:
		DecodeInt(d, (*int16)(up), tag)
	case reflect.Int32:
		DecodeInt(d, (*int32)(up), tag)
	case reflect.Int64:
		DecodeInt(d, (*int64)(up), tag)
	case reflect.Uint:
		DecodeUint(d, (*uint)(up), tag)
	case reflect.Uint8:
		DecodeUint(d, (*uint8)(up), tag)
	case reflect.Uint16:
		DecodeUint(d, (*uint16)(up), tag)
	case reflect.Uint32:
		DecodeUint(d, (*uint32)(up), tag)
	case reflect.Uint64:
		DecodeUint(d, (*uint64)(up), tag)
	case reflect.Uintptr:
		DecodeUint(d, (*uintptr)(up), tag)
	case reflect.Float32:
		DecodeFloat32(d, (*float32)(up), tag)
	case reflect.Float64:
		DecodeFloat64(d, (*float64)(up), tag)
	case reflect.Complex64:
		DecodeComplex64(d, (*complex64)(up), tag)
	case reflect.Complex128:
		DecodeComplex128(d, (*complex128)(up), tag)
	case reflect.String:
		DecodeString(d, (*string)(up), tag)
	case reflect.Ptr:
		d.pointer(up, typ.Elem(), tag)
	case reflect.Slice:
		if typ.Elem().Kind() != reflect.Uint8 {
			d.fallback(reflect.NewAt(typ, up).Elem(), tag)
			break
		}
		d.byteSlice(up, typ, tag)
	case reflect.Array:
		if typ.Elem().Kind() != reflect.Uint8 {
			d.fallback(reflect.NewAt(typ, up).Elem(), tag)
			break
		}
		d.byteArray(up, typ.Len(), tag)
	case reflect.Struct:
		if typ.NumField() != 0 {
			d.fallback(reflect.NewAt(typ, up).Elem(), tag)
			break
		}
		d.emptyStruct(up, typ, tag)
	case reflect.Interface:
		return d.iface(up, typ, tag)
	default:
		d.fallback(reflect.NewAt(typ, up).Elem(), tag)
	}
	return nil, false
}
