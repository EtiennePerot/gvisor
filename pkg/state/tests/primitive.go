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

package tests

import (
	"context"

	"gvisor.dev/gvisor/pkg/state"
)

// +stateify savable
type primitiveFields struct {
	b   bool
	s   string
	i   int
	i8  int8
	i16 int16
	i32 int32
	i64 int64
	u   uint
	u8  uint8
	u16 uint16
	u32 uint32
	u64 uint64
	up  uintptr
}

// truncatingField saves a uint64 field and loads it into a uint8, to check
// that integer truncation is an error.
type truncatingField struct {
	saved  uint64
	loaded uint8
}

func (*truncatingField) StateTypeName() string { return "pkg/state/tests.truncatingField" }

func (*truncatingField) StateFields() []string { return []string{"v"} }

func (t *truncatingField) StateSave(sink state.Sink) { sink.Save(0, &t.saved) }

func (t *truncatingField) StateLoad(_ context.Context, source state.Source) {
	source.Load(0, &t.loaded)
}

func init() {
	state.Register((*truncatingField)(nil))
}
