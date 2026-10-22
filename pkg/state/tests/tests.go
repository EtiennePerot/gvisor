// Copyright 2018 The gVisor Authors.
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

// Package tests tests the state packages.
package tests

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"reflect"
	"testing"

	"gvisor.dev/gvisor/pkg/state"
	"gvisor.dev/gvisor/pkg/state/pretty"
)

// checkEqual checks if two objects are equal.
//
// N.B. This only handles one level of dereferences for NaN. Otherwise we
// would need to fork the entire implementation of reflect.DeepEqual.
func checkEqual(root, loadedValue any) bool {
	if reflect.DeepEqual(root, loadedValue) {
		return true
	}

	// NaN is not equal to itself. We handle the case of raw floating point
	// primitives here, but don't handle this case nested.
	rf32, ok1 := root.(float32)
	lf32, ok2 := loadedValue.(float32)
	if ok1 && ok2 && math.IsNaN(float64(rf32)) && math.IsNaN(float64(lf32)) {
		return true
	}
	rf64, ok1 := root.(float64)
	lf64, ok2 := loadedValue.(float64)
	if ok1 && ok2 && math.IsNaN(rf64) && math.IsNaN(lf64) {
		return true
	}

	// Apply the same rule to both components of complex numbers.
	rc64, ok1 := root.(complex64)
	lc64, ok2 := loadedValue.(complex64)
	if ok1 && ok2 {
		return checkEqual(real(rc64), real(lc64)) && checkEqual(imag(rc64), imag(lc64))
	}
	rc128, ok1 := root.(complex128)
	lc128, ok2 := loadedValue.(complex128)
	if ok1 && ok2 {
		return checkEqual(real(rc128), real(lc128)) && checkEqual(imag(rc128), imag(lc128))
	}

	return false
}

// codecModes are the codec settings tested by runTestCases.
var codecModes = []struct {
	name   string
	codecs bool
}{
	{"reflect", false},
	{"codec", true},
}

// withCodecs runs fn with Codec methods enabled or disabled.
func withCodecs(codecs bool, fn func()) {
	if !codecs {
		defer state.DisableCodecs()()
	}
	fn()
}

// save saves root with codecs enabled or disabled.
func save(root any, codecs bool) ([]byte, state.Stats, error) {
	var (
		buf   bytes.Buffer
		stats state.Stats
		err   error
	)
	saveObjectPtr := reflect.New(reflect.TypeOf(root))
	saveObjectPtr.Elem().Set(reflect.ValueOf(root))
	withCodecs(codecs, func() {
		stats, err = state.Save(context.Background(), &buf, saveObjectPtr.Interface())
	})
	return buf.Bytes(), stats, err
}

// trailer is appended to encoded objects to check that Load does not consume
// data after the object.
const trailer = "trailer"

// load loads data into a new object of the given type, with codecs enabled
// or disabled. With codecs, data is read through a small bufio.Reader, which
// lets the decoder read from its buffer.
func load(typ reflect.Type, data []byte, codecs bool) (any, state.Stats, error) {
	var (
		stats state.Stats
		err   error
	)
	loadObjectPtr := reflect.New(typ)
	var r io.Reader = bytes.NewReader(append(data[:len(data):len(data)], trailer...))
	if codecs {
		r = bufio.NewReaderSize(r, 16)
	}
	withCodecs(codecs, func() {
		stats, err = state.Load(context.Background(), r, loadObjectPtr.Interface())
	})
	if err == nil {
		if rest, rerr := io.ReadAll(r); rerr != nil || string(rest) != trailer {
			err = fmt.Errorf("data after the object is %q, %v; want %q", rest, rerr, trailer)
		}
	}
	return loadObjectPtr.Elem().Interface(), stats, err
}

// containsMap returns true if v may refer to a map, whose encoding depends on
// iteration order.
func containsMap(typ reflect.Type, seen map[reflect.Type]bool) bool {
	if seen[typ] {
		return false
	}
	seen[typ] = true
	switch typ.Kind() {
	case reflect.Map, reflect.Interface:
		return true
	case reflect.Ptr, reflect.Slice, reflect.Array:
		return containsMap(typ.Elem(), seen)
	case reflect.Struct:
		for i := 0; i < typ.NumField(); i++ {
			if containsMap(typ.Field(i).Type, seen) {
				return true
			}
		}
	}
	return false
}

// runTestCases runs a test for each object in objects.
//
// Each object is saved and loaded both with and without Codec methods, and
// the results are cross-checked: both encoders must produce the same bytes
// (up to map iteration order), and each decoder must load the output of each
// encoder.
func runTestCases(t *testing.T, shouldFail bool, prefix string, objects []any) {
	t.Helper()
	for i, root := range objects {
		t.Run(fmt.Sprintf("%s%d", prefix, i), func(t *testing.T) {
			t.Logf("Original object:\n%#v", root)
			typ := reflect.TypeOf(root)

			var encoded [2][]byte
			for mi, sm := range codecModes {
				data, saveStats, err := save(root, sm.codecs)
				if err != nil {
					if shouldFail {
						continue
					}
					t.Fatalf("Save (%s) failed unexpectedly: %v", sm.name, err)
				}
				encoded[mi] = data

				// Dump the serialized proto to aid with debugging.
				var ppBuf bytes.Buffer
				t.Logf("Raw state (%s):\n%v", sm.name, data)
				if err := pretty.PrintText(&ppBuf, bytes.NewReader(data)); err != nil {
					// We don't count this as a test failure if we
					// have shouldFail set, but we will count as a
					// failure if we were not expecting to fail.
					if !shouldFail {
						t.Errorf("PrettyPrint(html=false) failed unexpected: %v", err)
					}
				}
				if err := pretty.PrintHTML(io.Discard, bytes.NewReader(data)); err != nil {
					// See above.
					if !shouldFail {
						t.Errorf("PrettyPrint(html=true) failed unexpected: %v", err)
					}
				}
				t.Logf("Encoded state (%s):\n%s", sm.name, ppBuf.String())
				t.Logf("Save stats:\n%s", saveStats.String())
			}
			if !shouldFail {
				if len(encoded[0]) != len(encoded[1]) || (!bytes.Equal(encoded[0], encoded[1]) && !containsMap(typ, make(map[reflect.Type]bool))) {
					t.Fatalf("Encodings differ:\n\treflect: %v\n\tcodec:   %v", encoded[0], encoded[1])
				}
			}

			failed := false
			for mi, sm := range codecModes {
				data := encoded[mi]
				if data == nil {
					failed = true
					continue
				}
				for _, lm := range codecModes {
					// Load a new copy of the object.
					loadedValue, loadStats, err := load(typ, data, lm.codecs)
					if err != nil {
						if shouldFail {
							failed = true
							continue
						}
						t.Fatalf("Load (%s of %s) failed unexpectedly: %v", lm.name, sm.name, err)
					}

					// Compare the values.
					if !checkEqual(root, loadedValue) {
						if shouldFail {
							failed = true
							continue
						}
						t.Fatalf("Objects differ (%s of %s):\n\toriginal: %#v\n\tloaded:   %#v\n", lm.name, sm.name, root, loadedValue)
					}
					t.Logf("Load stats:\n%s", loadStats.String())
					if shouldFail {
						continue
					}

					// Truncate half the bytes in the byte stream,
					// and ensure that we can't restore. Then
					// truncate only the final byte and ensure that
					// we can't restore.
					l := len(data)
					if _, _, err := load(typ, data[:l/2], lm.codecs); err == nil {
						t.Errorf("Load (%s of %s) with half bytes succeeded unexpectedly.", lm.name, sm.name)
					}
					if _, _, err := load(typ, data[:l-1], lm.codecs); err == nil {
						t.Errorf("Load (%s of %s) with missing byte succeeded unexpectedly.", lm.name, sm.name)
					}
				}
			}

			// Everything went okay. Is that good?
			if shouldFail && !failed {
				t.Fatalf("This test was expected to fail, but didn't.")
			}
		})
	}
}

// convert converts the slice to an []any.
func convert(v any) (r []any) {
	s := reflect.ValueOf(v) // Must be slice.
	for i := 0; i < s.Len(); i++ {
		r = append(r, s.Index(i).Interface())
	}
	return r
}

// flatten flattens multiple slices.
func flatten(vs ...any) (r []any) {
	for _, v := range vs {
		r = append(r, convert(v)...)
	}
	return r
}

// filter maps from one slice to another.
func filter(vs any, fn func(any) (any, bool)) (r []any) {
	s := reflect.ValueOf(vs)
	for i := 0; i < s.Len(); i++ {
		v, ok := fn(s.Index(i).Interface())
		if ok {
			r = append(r, v)
		}
	}
	return r
}

// combine combines objects in two slices as specified.
func combine(v1, v2 any, fn func(_, _ any) any) (r []any) {
	s1 := reflect.ValueOf(v1)
	s2 := reflect.ValueOf(v2)
	for i := 0; i < s1.Len(); i++ {
		for j := 0; j < s2.Len(); j++ {
			// Combine using the given function.
			r = append(r, fn(s1.Index(i).Interface(), s2.Index(j).Interface()))
		}
	}
	return r
}

// pointersTo is a filter function that returns pointers.
func pointersTo(vs any) []any {
	return filter(vs, func(o any) (any, bool) {
		v := reflect.New(reflect.TypeOf(o))
		v.Elem().Set(reflect.ValueOf(o))
		return v.Interface(), true
	})
}

// interfacesTo is a filter function that returns interface objects.
func interfacesTo(vs any) []any {
	return filter(vs, func(o any) (any, bool) {
		var v [1]any
		v[0] = o
		return v, true
	})
}
