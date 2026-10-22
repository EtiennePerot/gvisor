// Copyright 2024 The gVisor Authors.
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

package wire

import (
	"bufio"
	"bytes"
	"io"
	"testing"
)

// BenchmarkUintSave benchmarks saving a Uint. This benchmark is important
// because almost all types in this package boil down to Uints. So
// Uint.save() performance is critical for checkpoint performance.
func BenchmarkUintSave(b *testing.B) {
	w := Writer{Writer: bufio.NewWriter(io.Discard)}
	n := Uint(0xdeadbeef)
	for i := 0; i < b.N; i++ {
		n.save(&w)
	}
}

// TestBufferedReader checks that objects decoded from the buffer of a
// bufio.Reader are correct, and that Reader.Sync leaves the bufio.Reader at
// the end of the decoded objects.
func TestBufferedReader(t *testing.T) {
	var buf bytes.Buffer
	w := Writer{Writer: &buf}
	w.Buffer(64)
	var objs []Object
	for i := 0; i < 100; i++ {
		s := String(bytes.Repeat([]byte{'x'}, i))
		objs = append(objs, Uint(1)<<(i%64), Int(-i)<<(i%60), &s)
	}
	for _, obj := range objs {
		Save(&w, obj)
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}
	const trailer = "trailer"
	buf.WriteString(trailer)

	for _, size := range []int{16, 64, 4096} {
		br := bufio.NewReaderSize(bytes.NewReader(buf.Bytes()), size)
		r := Reader{Reader: br}
		for i, want := range objs {
			got := Load(&r)
			if s, ok := want.(*String); ok {
				if gs, ok := got.(*String); !ok || *gs != *s {
					t.Fatalf("size %d: object %d: got %#v, want %#v", size, i, got, want)
				}
				continue
			}
			if got != want {
				t.Fatalf("size %d: object %d: got %#v, want %#v", size, i, got, want)
			}
		}
		r.Sync()
		rest, err := io.ReadAll(br)
		if err != nil || string(rest) != trailer {
			t.Errorf("size %d: got rest %q, %v; want %q", size, rest, err, trailer)
		}
	}
}
