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

// Package foreign contains types whose kind is unknown to go_stateify when
// they are used in other packages.
package foreign

// Bytes is a slice of bytes.
type Bytes []byte

// Array is an array of bytes.
type Array [5]byte

// Empty is an unregistered struct without fields.
type Empty struct{}

// Ints is a slice of integers.
type Ints []int32
