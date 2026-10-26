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
	"reflect"
	"unsafe"
)

// methods holds the state methods of a struct type with a nil receiver.
type methods struct {
	saverLoader SaverLoader
	binary      binaryObject
}

// makeMethods returns the state methods of typ.
func makeMethods(typ reflect.Type) methods {
	if typ.Kind() != reflect.Struct {
		return methods{}
	}
	v := reflect.Zero(reflect.PointerTo(typ)).Interface()
	sl, _ := v.(SaverLoader)
	b, _ := v.(binaryObject)
	return methods{saverLoader: sl, binary: b}
}

// saverLoaderAt returns m.saverLoader with obj's address as receiver.
//
// Preconditions: obj.CanAddr() and obj has the type passed to makeMethods.
func (m *methods) saverLoaderAt(obj reflect.Value) SaverLoader {
	sl := m.saverLoader
	(*[2]unsafe.Pointer)(unsafe.Pointer(&sl))[1] = unsafe.Pointer(obj.UnsafeAddr())
	return sl
}

// binaryAt returns m.binary with obj's address as receiver.
//
// Preconditions: obj.CanAddr() and obj has the type passed to makeMethods.
func (m *methods) binaryAt(obj reflect.Value) binaryObject {
	b := m.binary
	(*[2]unsafe.Pointer)(unsafe.Pointer(&b))[1] = unsafe.Pointer(obj.UnsafeAddr())
	return b
}
