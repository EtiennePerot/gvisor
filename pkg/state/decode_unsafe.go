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
	"sync"
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

// ifacePair is an (interface type, concrete type) pair.
type ifacePair struct {
	iface    reflect.Type
	concrete reflect.Type
}

// ifaceWords maps an ifacePair to the first word (itab or type pointer) of
// an interface value holding the concrete type.
var ifaceWords sync.Map // ifacePair -> unsafe.Pointer

// setInterface is equivalent to iface.Set(obj), where iface is of interface
// kind. It skips the reflect.Value.Set method-set check (which is not cached)
// for pairs of types that have already been checked.
//
// Preconditions: obj is not of interface kind and is not read-only.
func setInterface(iface, obj reflect.Value) {
	pair := ifacePair{iface.Type(), obj.Type()}
	word, ok := ifaceWords.Load(pair)
	if !ok || !iface.CanSet() {
		iface.Set(obj)
		ifaceWords.Store(pair, (*[2]unsafe.Pointer)(unsafe.Pointer(iface.UnsafeAddr()))[0])
		return
	}
	// Both interface kinds start with a type word followed by a data word.
	// The data word of an any holding obj is the data word that Set stores.
	v := obj.Interface()
	*(*[2]unsafe.Pointer)(unsafe.Pointer(iface.UnsafeAddr())) = [2]unsafe.Pointer{word.(unsafe.Pointer), (*[2]unsafe.Pointer)(unsafe.Pointer(&v))[1]}
}
