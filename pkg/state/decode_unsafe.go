// Copyright 2020 The gVisor Authors.
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
	"fmt"
	"reflect"
	"unsafe"
)

// reflectValueRWAddr is equivalent to obj.Addr(), except that the returned
// reflect.Value is usable in assignments even if obj was obtained by the use
// of unexported struct fields.
//
// Preconditions: obj.CanAddr().
func reflectValueRWAddr(obj reflect.Value) reflect.Value {
	return reflect.NewAt(obj.Type(), unsafe.Pointer(obj.UnsafeAddr()))
}

// reflectValueRWSlice3 is equivalent to arr.Slice3(i, j, k), except that the
// returned reflect.Value is usable in assignments even if obj was obtained by
// the use of unexported struct fields.
//
// Preconditions:
//   - arr.Kind() == reflect.Array and arr.CanAddr().
//   - i, j, k >= 0.
//   - i <= j <= k <= arr.Len().
func reflectValueRWSlice3(arr reflect.Value, i, j, k int) reflect.Value {
	if arr.Kind() != reflect.Array {
		panic(fmt.Sprintf("arr has kind %v, wanted %v", arr.Kind(), reflect.Array))
	}
	return reflectValueRWAddr(arr).Elem().Slice3(i, j, k)
}

// ifaceCache caches the type words (interface tables or, for empty
// interfaces, types) of interface values by interface type and dynamic type.
//
// reflect.Value.Set checks that the type of the assigned value implements the
// interface on every call, by walking their method sets, and doesn't cache
// the result. ifaceCache makes this check once per pair of types.
type ifaceCache map[ifaceKey]unsafe.Pointer

// ifaceKey identifies an interface type and the dynamic type of a value
// assigned to an interface of that type.
type ifaceKey struct {
	iface reflect.Type
	// typ is the type word of an empty interface holding the value.
	typ unsafe.Pointer
}

// set sets the interface of type ityp at p to v, which must not be nil. It is
// equivalent to reflect.NewAt(ityp, p).Elem().Set(reflect.ValueOf(v)).
func (c *ifaceCache) set(p unsafe.Pointer, ityp reflect.Type, v any) {
	// Interfaces are a type word followed by a data word, and the data
	// word of an interface holding v is the same as v's.
	e := (*[2]unsafe.Pointer)(unsafe.Pointer(&v))
	key := ifaceKey{ityp, e[0]}
	if word, ok := (*c)[key]; ok {
		*(*[2]unsafe.Pointer)(p) = [2]unsafe.Pointer{word, e[1]}
		return
	}
	reflect.NewAt(ityp, p).Elem().Set(reflect.ValueOf(v))
	if *c == nil {
		*c = make(ifaceCache)
	}
	(*c)[key] = (*[2]unsafe.Pointer)(p)[0]
}

// setValue is equivalent to iface.Set(v), where iface is an addressable
// interface and v is not an interface.
func (c *ifaceCache) setValue(iface, v reflect.Value) {
	c.set(unsafe.Pointer(iface.UnsafeAddr()), iface.Type(), v.Interface())
}
