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
	"encoding/hex"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/state"
)

func largeByteArray() [11 * 1024]byte {
	var arr [11 * 1024]byte
	for i := range arr {
		arr[i] = byte(i * 7)
	}
	return arr
}

func byteArrayContainerValue() *byteArrayContainer {
	c := &byteArrayContainer{
		named: [3]namedByte{1, 0, 255},
		slice: []byte("hello, world")[:5],
		v:     [4]byte{4, 3, 2, 1},
	}
	for i := range c.arr {
		c.arr[i] = byte(0x80 + i)
	}
	c.elem = &c.arr[5]
	return c
}

func TestByteArrays(t *testing.T) {
	runTestCases(t, false, "", []any{
		[0]byte{},
		[1]byte{},
		[1]byte{1},
		[3]namedByte{1, 2, 3},
		largeByteArray(),
		[2][3]byte{{1, 2, 3}, {4, 5, 6}},
		map[[2]byte][2]byte{{1, 2}: {3, 4}, {5, 6}: {7, 8}},
		[]any{[2]byte{1, 2}, [0]byte{}},
		byteArrayContainerValue(),
		byteArrayContainer{v: [1]byte{9}},
	})
}

func TestByteArrayInteriorPointer(t *testing.T) {
	var buf bytes.Buffer
	if _, err := state.Save(context.Background(), &buf, byteArrayContainerValue()); err != nil {
		t.Fatalf("Save failed: %v", err)
	}
	var got byteArrayContainer
	if _, err := state.Load(context.Background(), bytes.NewReader(buf.Bytes()), &got); err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if got.elem != &got.arr[5] {
		t.Errorf("elem does not point into arr")
	}
	if *got.elem != 0x85 {
		t.Errorf("*elem = %#x, want 0x85", *got.elem)
	}
}

// TestByteArrayEncodingSize checks that byte arrays are encoded in bulk, not
// as one value per byte.
func TestByteArrayEncodingSize(t *testing.T) {
	arr := largeByteArray()
	var buf bytes.Buffer
	if _, err := state.Save(context.Background(), &buf, &arr); err != nil {
		t.Fatalf("Save failed: %v", err)
	}
	if max := len(arr) + 64; buf.Len() > max {
		t.Errorf("encoded %d byte array in %d bytes, want at most %d", len(arr), buf.Len(), max)
	}
}

func TestByteArrayMismatch(t *testing.T) {
	arr := [4]byte{1, 2, 3, 4}
	var buf bytes.Buffer
	if _, err := state.Save(context.Background(), &buf, &arr); err != nil {
		t.Fatalf("Save failed: %v", err)
	}
	for _, tc := range []struct {
		name string
		obj  any
		want string
	}{
		{name: "length", obj: new([5]byte), want: "mismatching array length"},
		{name: "type", obj: new([4]uint16), want: "byte array decoded into"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := state.Load(context.Background(), bytes.NewReader(buf.Bytes()), tc.obj)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Load got error %v, want %q", err, tc.want)
			}
		})
	}
}

// TestLegacyByteArrays checks that byte arrays encoded as one value per byte,
// as by older versions of this package, still decode.
func TestLegacyByteArrays(t *testing.T) {
	for _, tc := range []struct {
		name    string
		encoded string
		obj     any
		want    any
	}{
		{
			name:    "array",
			encoded: "81808080808080808001020109040201028001ff01",
			obj:     new([4]byte),
			want:    &[4]byte{1, 2, 0x80, 0xff},
		},
		{
			name:    "named",
			encoded: "8180808080808080800102010903020100ff01",
			obj:     new([3]namedByte),
			want:    &[3]namedByte{1, 0, 255},
		},
		{
			name: "container",
			encoded: "" +
				"828080808080808080011122706b672f73746174652f74657374732e62797465" +
				"4172726179436f6e7461696e65720503617272056e616d656405736c69636504" +
				"656c656d0176110575696e74380002010b010d05091002800181018201830184" +
				"01850186018701880189018a018b018c018d018e018f010903020100ff010805" +
				"0c02000601020a0561727200010e02040002090402040302010202090c026865" +
				"6c6c6f00000000000000",
			obj:  new(byteArrayContainer),
			want: byteArrayContainerValue(),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := hex.DecodeString(tc.encoded)
			if err != nil {
				t.Fatalf("bad test encoding: %v", err)
			}
			if _, err := state.Load(context.Background(), bytes.NewReader(b), tc.obj); err != nil {
				t.Fatalf("Load failed: %v", err)
			}
			if !checkEqual(tc.want, tc.obj) {
				t.Errorf("Load got %#v, want %#v", tc.obj, tc.want)
			}
		})
	}
}
