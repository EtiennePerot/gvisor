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
	"math"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/state"
)

func TestPrimitiveFields(t *testing.T) {
	runTestCases(t, false, "", []any{
		primitiveFields{},
		primitiveFields{
			b:   true,
			s:   "foo",
			i:   math.MinInt,
			i8:  math.MinInt8,
			i16: math.MinInt16,
			i32: math.MinInt32,
			i64: math.MinInt64,
			u:   1,
			u8:  1,
			u16: 1,
			u32: 1,
			u64: 1,
			up:  1,
		},
		primitiveFields{
			i:   math.MaxInt,
			i8:  math.MaxInt8,
			i16: math.MaxInt16,
			i32: math.MaxInt32,
			i64: math.MaxInt64,
			u:   math.MaxUint,
			u8:  math.MaxUint8,
			u16: math.MaxUint16,
			u32: math.MaxUint32,
			u64: math.MaxUint64,
			up:  math.MaxUint64,
		},
		&primitiveFields{s: "bar", u32: 7},
	})
}

func TestPrimitiveFieldTruncation(t *testing.T) {
	for _, tc := range []struct {
		saved uint64
		want  string
	}{
		{saved: 0},
		{saved: math.MaxUint8},
		{saved: math.MaxUint8 + 1, want: "unsigned integer truncated"},
	} {
		var buf bytes.Buffer
		if _, err := state.Save(context.Background(), &buf, &truncatingField{saved: tc.saved}); err != nil {
			t.Fatalf("Save failed: %v", err)
		}
		var got truncatingField
		_, err := state.Load(context.Background(), bytes.NewReader(buf.Bytes()), &got)
		if tc.want == "" {
			if err != nil {
				t.Errorf("Load(%d) failed: %v", tc.saved, err)
			} else if uint64(got.loaded) != tc.saved {
				t.Errorf("Load(%d) got %d", tc.saved, got.loaded)
			}
		} else if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("Load(%d) got error %v, want %q", tc.saved, err, tc.want)
		}
	}
}
