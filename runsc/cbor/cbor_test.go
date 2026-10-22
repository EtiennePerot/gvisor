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

package cbor

import (
	"bytes"
	"encoding/json"
	"math"
	"math/rand"
	"strconv"
	"testing"
	"time"

	fxcbor "github.com/fxamacker/cbor/v2"
	"github.com/google/go-cmp/cmp"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// counter has custom serialization, like runsc's sandbox.Pid.
type counter struct {
	n int64
}

func (c *counter) MarshalCBOR() ([]byte, error) { return Marshal(strconv.FormatInt(c.n, 10)) }

func (c *counter) UnmarshalCBOR(b []byte) error {
	var s string
	if err := Unmarshal(b, &s); err != nil {
		return err
	}
	var err error
	c.n, err = strconv.ParseInt(s, 10, 64)
	return err
}

func (c *counter) MarshalJSON() ([]byte, error) { return json.Marshal(strconv.FormatInt(c.n, 10)) }

func (c *counter) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	var err error
	c.n, err = strconv.ParseInt(s, 10, 64)
	return err
}

type Embedded struct {
	E1 string `json:"e1"`
	E2 int    `json:"e2"`
	// Shadowed by all.E3.
	E3 int `json:"e3"`
}

type embeddedUnexported struct {
	U1 string `json:"u1"`
	// Shadowed by all.Same2.
	Same int
}

type all struct {
	Embedded
	embeddedUnexported
	Same2 int `json:"Same"`

	Bool     bool    `json:"bool"`
	Int      int     `json:"int"`
	Int8     int8    `json:"int8"`
	Int16    int16   `json:"int16"`
	Int32    int32   `json:"int32"`
	Int64    int64   `json:"int64"`
	Uint     uint    `json:"uint"`
	Uint8    uint8   `json:"uint8"`
	Uint16   uint16  `json:"uint16"`
	Uint32   uint32  `json:"uint32"`
	Uint64   uint64  `json:"uint64"`
	Float32  float32 `json:"float32"`
	Float64  float64 `json:"float64"`
	String   string  `json:"string"`
	Untagged string
	E3       string            `json:"e3"`
	Ptr      *Embedded         `json:"ptr"`
	NilPtr   *Embedded         `json:"nilPtr"`
	Slice    []string          `json:"slice"`
	Empty    []string          `json:"empty"`
	NilSl    []string          `json:"nilSlice"`
	Map      map[string]int    `json:"map"`
	IntMap   map[int32]string  `json:"intMap"`
	NilMap   map[string]string `json:"nilMap"`
	Structs  []Embedded        `json:"structs"`
	PtrMap   map[string]*Embedded
	Any      any       `json:"any"`
	Time     time.Time `json:"time"`
	Counter  counter   `json:"counter"`
	Omit     string    `json:"omit,omitempty"`
	OmitPtr  *int      `json:"omitPtr,omitempty"`
	OmitSet  int       `json:"omitSet,omitempty"`
	Skipped  string    `json:"-"`
	Dash     string    `json:"-,"`

	unexported int
}

func testValue() *all {
	return &all{
		Embedded:           Embedded{E1: "e1", E2: -2, E3: 3},
		embeddedUnexported: embeddedUnexported{U1: "u1", Same: 4},
		Same2:              5,
		Bool:               true,
		Int:                math.MinInt,
		Int8:               math.MinInt8,
		Int16:              math.MaxInt16,
		Int32:              -1 << 20,
		Int64:              math.MaxInt64,
		Uint:               math.MaxUint,
		Uint8:              math.MaxUint8,
		Uint16:             1000,
		Uint32:             math.MaxUint32,
		Uint64:             1 << 40,
		Float32:            1.5,
		Float64:            -math.Pi,
		String:             "héllo, wörld",
		Untagged:           "untagged",
		E3:                 "outer",
		Ptr:                &Embedded{E1: "ptr"},
		Slice:              []string{"a", "", "c"},
		Empty:              []string{},
		Map:                map[string]int{"one": 1, "two": 2},
		IntMap:             map[int32]string{-1: "minus one", 1 << 30: "big"},
		Structs:            []Embedded{{E1: "s1"}, {E2: 2}},
		PtrMap:             map[string]*Embedded{"nil": nil, "set": {E1: "set"}},
		Any:                map[string]any{"list": []any{1.0, "two", true, nil}, "num": 3.5},
		Time:               time.Date(2026, 10, 21, 1, 2, 3, 456789123, time.FixedZone("test", -7*3600)),
		Counter:            counter{n: 42},
		OmitSet:            7,
		Skipped:            "not encoded",
		Dash:               "dash",
		unexported:         8,
	}
}

func TestRoundTrip(t *testing.T) {
	want := testValue()
	data, err := Marshal(want)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got all
	if err := Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	// Not encoded.
	want.Skipped = ""
	want.unexported = 0
	// Shadowed, like encoding/json does.
	want.Embedded.E3 = 0
	want.embeddedUnexported.Same = 0
	if diff := cmp.Diff(want, &got, cmp.AllowUnexported(all{}, counter{}, embeddedUnexported{})); diff != "" {
		t.Errorf("round trip differs (-want +got):\n%s", diff)
	}
	if !got.Time.Equal(want.Time) {
		t.Errorf("time: got %v, want %v", got.Time, want.Time)
	}
}

// TestMatchesJSON checks that values are encoded with the same structure,
// fields and field names as encoding/json uses.
func TestMatchesJSON(t *testing.T) {
	for _, v := range []any{testValue(), testSpec()} {
		data, err := Marshal(v)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		var got any
		if err := Unmarshal(data, &got); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		jsonData, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		var want any
		if err := json.Unmarshal(jsonData, &want); err != nil {
			t.Fatalf("json.Unmarshal: %v", err)
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("%T: generic decoding differs from JSON (-json +cbor):\n%s", v, diff)
		}
	}
}

func testSpec() *specs.Spec {
	return &specs.Spec{
		Version: "1.2.1",
		Process: &specs.Process{
			User:         specs.User{UID: 1, GID: 2, AdditionalGids: []uint32{3}},
			Args:         []string{"/bin/sh"},
			Env:          []string{"PATH=/bin"},
			Cwd:          "/",
			Capabilities: &specs.LinuxCapabilities{Bounding: []string{"CAP_CHOWN"}},
			Rlimits:      []specs.POSIXRlimit{{Type: "RLIMIT_NOFILE", Hard: 1 << 20, Soft: 1 << 20}},
		},
		Root:        &specs.Root{Path: "rootfs"},
		Mounts:      []specs.Mount{{Destination: "/proc", Type: "proc", Source: "proc", Options: []string{"nosuid"}}},
		Annotations: map[string]string{"key": "value"},
		Linux: &specs.Linux{
			Resources: &specs.LinuxResources{
				Memory:  &specs.LinuxMemory{Limit: new(int64(1 << 30))},
				Devices: []specs.LinuxDeviceCgroup{{Allow: false, Access: "rwm"}},
			},
			Namespaces: []specs.LinuxNamespace{{Type: specs.PIDNamespace}},
			Seccomp: &specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno,
				Syscalls: []specs.LinuxSyscall{{
					Names:  []string{"read", "write"},
					Action: specs.ActAllow,
					Args:   []specs.LinuxSeccompArg{{Index: 1, Value: 2, Op: specs.OpEqualTo}},
				}},
			},
		},
	}
}

// TestInterop checks that the encoding can be decoded by another CBOR
// implementation, and the other way around.
func TestInterop(t *testing.T) {
	want := testSpec()
	data, err := Marshal(want)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got specs.Spec
	if err := fxcbor.Unmarshal(data, &got); err != nil {
		t.Fatalf("fxcbor.Unmarshal: %v", err)
	}
	if diff := cmp.Diff(want, &got); diff != "" {
		t.Errorf("fxcbor decoding differs (-want +got):\n%s", diff)
	}

	em, err := fxcbor.EncOptions{Time: fxcbor.TimeRFC3339Nano}.EncMode()
	if err != nil {
		t.Fatalf("EncMode: %v", err)
	}
	if data, err = em.Marshal(want); err != nil {
		t.Fatalf("fxcbor.Marshal: %v", err)
	}
	got = specs.Spec{}
	if err := Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if diff := cmp.Diff(want, &got); diff != "" {
		t.Errorf("decoding of fxcbor encoding differs (-want +got):\n%s", diff)
	}
}

type v1 struct {
	A string `json:"a"`
	C []int  `json:"c"`
}

type v2 struct {
	A string            `json:"a"`
	B map[string][]bool `json:"b"`
	C []int             `json:"c"`
	D *v1               `json:"d"`
}

// TestOtherVersions checks that unknown fields are ignored and that missing
// fields are left unchanged.
func TestOtherVersions(t *testing.T) {
	data, err := Marshal(&v2{A: "a", B: map[string][]bool{"b": {true}}, C: []int{1}, D: &v1{A: "d"}})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var old v1
	if err := Unmarshal(data, &old); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if diff := cmp.Diff(v1{A: "a", C: []int{1}}, old); diff != "" {
		t.Errorf("decoding into older version differs (-want +got):\n%s", diff)
	}

	if data, err = Marshal(&v1{A: "a", C: []int{1}}); err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	newer := v2{B: map[string][]bool{"unchanged": nil}}
	if err := Unmarshal(data, &newer); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if diff := cmp.Diff(v2{A: "a", B: map[string][]bool{"unchanged": nil}, C: []int{1}}, newer); diff != "" {
		t.Errorf("decoding into newer version differs (-want +got):\n%s", diff)
	}
}

func TestNull(t *testing.T) {
	null := []byte{0xf6}
	v := testValue()
	for _, p := range []any{&v.Bool, &v.Int, &v.Uint, &v.Float64, &v.String, &v.Time, &v.Embedded} {
		before, _ := json.Marshal(p)
		if err := Unmarshal(null, p); err != nil {
			t.Fatalf("Unmarshal(null, %T): %v", p, err)
		}
		if after, _ := json.Marshal(p); !bytes.Equal(before, after) {
			t.Errorf("Unmarshal(null, %T) changed %s to %s", p, before, after)
		}
	}
	for _, p := range []any{&v.Ptr, &v.Slice, &v.Map, &v.Any} {
		if err := Unmarshal(null, p); err != nil {
			t.Fatalf("Unmarshal(null, %T): %v", p, err)
		}
		if b, _ := json.Marshal(p); string(b) != "null" {
			t.Errorf("Unmarshal(null, %T) = %s, want null", p, b)
		}
	}
}

func TestDecodeErrors(t *testing.T) {
	data, err := Marshal(testValue())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for n := 0; n < len(data); n++ {
		var v all
		if err := Unmarshal(data[:n], &v); err == nil {
			t.Errorf("Unmarshal of %d/%d bytes succeeded", n, len(data))
		}
	}
	var v all
	if err := Unmarshal(append(data, 0), &v); err == nil {
		t.Errorf("Unmarshal with trailing data succeeded")
	}

	for _, tc := range []struct {
		name string
		data []byte
		v    any
	}{
		{name: "overflow", data: mustMarshal(t, 300), v: new(int8)},
		{name: "negative into uint", data: mustMarshal(t, -1), v: new(uint)},
		{name: "string into int", data: mustMarshal(t, "1"), v: new(int)},
		{name: "int into string", data: mustMarshal(t, 1), v: new(string)},
		{name: "array into struct", data: mustMarshal(t, []int{1}), v: new(v1)},
		{name: "bad time", data: mustMarshal(t, "yesterday"), v: new(time.Time)},
		{name: "indefinite length", data: []byte{0x9f, 0xff}, v: new([]int)},
		{name: "huge length", data: []byte{0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, v: new([]int)},
		{name: "deeply nested unknown field", data: append([]byte{0xa1, 0x61, 'x'}, append(bytes.Repeat([]byte{0x81}, 1000), 0)...), v: new(v1)},
		{name: "not a pointer", data: mustMarshal(t, 1), v: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := Unmarshal(tc.data, tc.v); err == nil {
				t.Errorf("Unmarshal succeeded")
			}
		})
	}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	data, err := Marshal(v)
	if err != nil {
		t.Fatalf("Marshal(%v): %v", v, err)
	}
	return data
}

// TestCorruptData checks that decoding random corruptions of valid data
// fails cleanly or succeeds, but doesn't panic.
func TestCorruptData(t *testing.T) {
	data, err := Marshal(testValue())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 10000; i++ {
		corrupt := append([]byte{}, data...)
		for j := 0; j < 1+rng.Intn(4); j++ {
			corrupt[rng.Intn(len(corrupt))] = byte(rng.Intn(256))
		}
		var v all
		_ = Unmarshal(corrupt, &v)
	}
}

func TestUnsupported(t *testing.T) {
	type withChan struct{ C chan int }
	type withMethods struct{ E error }
	type withEmbeddedPointer struct{ *Embedded }
	for _, v := range []any{
		make(chan int),
		func() {},
		complex(1, 2),
		[2]int{1, 2},
		map[[2]int]int{{1, 2}: 3},
		withChan{C: make(chan int)},
		withMethods{E: nil},
		withEmbeddedPointer{&Embedded{}},
	} {
		if _, err := Marshal(v); err == nil {
			t.Errorf("Marshal(%T) succeeded", v)
		}
	}
}

// FuzzUnmarshal checks that decoding arbitrary data fails cleanly or
// succeeds, and that values that decode successfully are encoded and decoded
// again without changes.
func FuzzUnmarshal(f *testing.F) {
	for _, v := range []any{testValue(), &v2{A: "a", B: map[string][]bool{"b": {true}}}, nil} {
		data, err := Marshal(v)
		if err != nil {
			f.Fatalf("Marshal: %v", err)
		}
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var v all
		if err := Unmarshal(data, &v); err != nil {
			return
		}
		want, err := json.Marshal(&v)
		if err != nil {
			// E.g. NaN, which JSON can't represent.
			return
		}
		enc, err := Marshal(&v)
		if err != nil {
			t.Fatalf("Marshal(%s): %v", want, err)
		}
		var got all
		if err := Unmarshal(enc, &got); err != nil {
			t.Fatalf("Unmarshal(Marshal(%s)): %v", want, err)
		}
		if gotJSON, err := json.Marshal(&got); err != nil || !bytes.Equal(gotJSON, want) {
			t.Errorf("round trip changed %s to %s (%v)", want, gotJSON, err)
		}
	})
}
