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
	"bytes"
	"context"
	"testing"

	"gvisor.dev/gvisor/pkg/state"
)

func TestInterfacePointers(t *testing.T) {
	c := byteArrayContainerValue()
	runTestCases(t, false, "", []any{
		genericContainer{v: (*primitiveFields)(nil)},
		genericContainer{v: &primitiveFields{u8: 3}},
		genericContainer{v: &c.arr[3]},
		genericContainer{v: c},
	})
}

// TestInterfaceInteriorPointer checks that a pointer held in an interface
// into another object is restored as such.
func TestInterfaceInteriorPointer(t *testing.T) {
	c := byteArrayContainerValue()
	c.v = &c.arr[7]
	var buf bytes.Buffer
	if _, err := state.Save(context.Background(), &buf, c); err != nil {
		t.Fatalf("Save failed: %v", err)
	}
	var got byteArrayContainer
	if _, err := state.Load(context.Background(), bytes.NewReader(buf.Bytes()), &got); err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if p, ok := got.v.(*byte); !ok || p != &got.arr[7] {
		t.Errorf("got.v = %#v, want pointer to got.arr[7] (%p)", got.v, &got.arr[7])
	}
}
