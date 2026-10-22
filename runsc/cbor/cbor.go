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

// Package cbor encodes Go values with the subset of CBOR (RFC 8949) that
// corresponds to JSON, using the same struct field names and options as
// encoding/json.
//
// It exists because runsc commands are short-lived processes: decoding a value
// once with encoding/json in a new process is expensive, mostly due to the
// reflection work that encoding/json does on first use of each type. This
// package does less of that work, only for the types present in the encoded
// data, and parsing CBOR is cheaper than parsing JSON. It is much smaller than
// general-purpose CBOR packages, which matters for the size of runsc.
//
// Values are encoded as follows:
//   - Booleans, integers, floats (as 64-bit floats), strings and byte slices
//     are encoded as the corresponding CBOR types.
//   - Nil pointers, slices, maps and interfaces are encoded as null.
//   - Slices are encoded as arrays.
//   - Maps are encoded as maps. Keys must be strings or integers.
//   - Structs are encoded as maps keyed by field name. Fields are selected
//     and named like encoding/json does: `json:"-"` fields are skipped,
//     `json:"name"` renames a field, `omitempty` omits empty values, and the
//     fields of embedded structs are promoted.
//   - time.Time is encoded as a string, in RFC 3339 format with nanoseconds.
//   - Types implementing Marshaler and Unmarshaler encode themselves.
//
// Decoding ignores map keys that don't name a struct field and leaves fields
// that are not in the data unchanged, like encoding/json, so that values
// remain decodable when fields are added or removed.
package cbor

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Marshaler is implemented by types that encode themselves. MarshalCBOR must
// return a single well-formed CBOR data item.
type Marshaler interface {
	MarshalCBOR() ([]byte, error)
}

// Unmarshaler is implemented by types that decode themselves. UnmarshalCBOR
// is passed a single well-formed CBOR data item.
type Unmarshaler interface {
	UnmarshalCBOR([]byte) error
}

// CBOR major types.
const (
	majorUint   = 0
	majorNegInt = 1
	majorBytes  = 2
	majorText   = 3
	majorArray  = 4
	majorMap    = 5
	majorTag    = 6
	majorSimple = 7
)

// Encodings of simple values and floats (major type 7).
const (
	simpleFalse   = 0xf4
	simpleTrue    = 0xf5
	simpleNull    = 0xf6
	simpleFloat32 = 0xfa
	simpleFloat64 = 0xfb
)

// maxDepth bounds the nesting of decoded data items.
const maxDepth = 64

var (
	marshalerType   = reflect.TypeFor[Marshaler]()
	unmarshalerType = reflect.TypeFor[Unmarshaler]()
	timeType        = reflect.TypeFor[time.Time]()

	errShort = errors.New("cbor: unexpected end of data")
)

// Marshal returns the CBOR encoding of v.
func Marshal(v any) ([]byte, error) {
	return Append(nil, v)
}

// Append appends the CBOR encoding of v to b.
func Append(b []byte, v any) ([]byte, error) {
	rv := reflect.ValueOf(v)
	if !rv.IsValid() {
		return append(b, simpleNull), nil
	}
	return codecFor(rv.Type()).enc(b, rv)
}

// Unmarshal decodes the CBOR data item in data into v, which must be a
// non-nil pointer.
func Unmarshal(data []byte, v any) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return fmt.Errorf("cbor: Unmarshal needs a non-nil pointer, got %T", v)
	}
	d := decoder{buf: data}
	if err := codecFor(rv.Type().Elem()).dec(&d, rv.Elem()); err != nil {
		return err
	}
	if len(d.buf) != 0 {
		return fmt.Errorf("cbor: %d bytes of trailing data", len(d.buf))
	}
	return nil
}

type encFn func(b []byte, v reflect.Value) ([]byte, error)
type decFn func(d *decoder, v reflect.Value) error

type codec struct {
	enc encFn
	dec decFn
}

var codecs sync.Map // reflect.Type -> *codec

func codecFor(t reflect.Type) *codec {
	if c, ok := codecs.Load(t); ok {
		return c.(*codec)
	}
	c := &codec{}
	c.enc, c.dec = makeCodec(t)
	codecs.Store(t, c)
	return c
}

// lazyCodec is the codec of a child type, built on first use. Thus the codecs
// of types that don't appear in the encoded values (e.g. behind nil pointers)
// are never built.
type lazyCodec struct {
	t reflect.Type
	c atomic.Pointer[codec]
}

func (l *lazyCodec) get() *codec {
	if c := l.c.Load(); c != nil {
		return c
	}
	c := codecFor(l.t)
	l.c.Store(c)
	return c
}

func unsupported(t reflect.Type) (encFn, decFn) {
	err := fmt.Errorf("cbor: unsupported type %v", t)
	return func([]byte, reflect.Value) ([]byte, error) { return nil, err },
		func(*decoder, reflect.Value) error { return err }
}

func makeCodec(t reflect.Type) (encFn, decFn) {
	if t.Kind() != reflect.Pointer && reflect.PointerTo(t).Implements(marshalerType) {
		if !reflect.PointerTo(t).Implements(unmarshalerType) {
			return unsupported(t)
		}
		return marshalerCodec()
	}
	if t == timeType {
		return timeCodec()
	}
	switch t.Kind() {
	case reflect.Bool:
		return func(b []byte, v reflect.Value) ([]byte, error) {
				if v.Bool() {
					return append(b, simpleTrue), nil
				}
				return append(b, simpleFalse), nil
			}, func(d *decoder, v reflect.Value) error {
				x, err := d.readByte()
				switch {
				case err != nil:
					return err
				case x == simpleTrue || x == simpleFalse:
					v.SetBool(x == simpleTrue)
					return nil
				case x == simpleNull:
					return nil
				}
				return fmt.Errorf("cbor: cannot decode %#x into %v", x, v.Type())
			}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return func(b []byte, v reflect.Value) ([]byte, error) {
				return appendInt(b, v.Int()), nil
			}, func(d *decoder, v reflect.Value) error {
				major, arg, null, err := d.readHead()
				if err != nil || null {
					return err
				}
				var x int64
				switch {
				case major == majorUint && arg <= math.MaxInt64:
					x = int64(arg)
				case major == majorNegInt && arg <= math.MaxInt64:
					x = -1 - int64(arg)
				default:
					return mismatch(major, v.Type())
				}
				if v.OverflowInt(x) {
					return fmt.Errorf("cbor: %d overflows %v", x, v.Type())
				}
				v.SetInt(x)
				return nil
			}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return func(b []byte, v reflect.Value) ([]byte, error) {
				return appendHead(b, majorUint, v.Uint()), nil
			}, func(d *decoder, v reflect.Value) error {
				major, arg, null, err := d.readHead()
				if err != nil || null {
					return err
				}
				if major != majorUint {
					return mismatch(major, v.Type())
				}
				if v.OverflowUint(arg) {
					return fmt.Errorf("cbor: %d overflows %v", arg, v.Type())
				}
				v.SetUint(arg)
				return nil
			}
	case reflect.Float32, reflect.Float64:
		return func(b []byte, v reflect.Value) ([]byte, error) {
				return binary.BigEndian.AppendUint64(append(b, simpleFloat64), math.Float64bits(v.Float())), nil
			}, func(d *decoder, v reflect.Value) error {
				x, null, err := d.readFloat()
				if err == nil && !null {
					v.SetFloat(x)
				}
				return err
			}
	case reflect.String:
		return func(b []byte, v reflect.Value) ([]byte, error) {
				return appendString(b, majorText, v.String()), nil
			}, func(d *decoder, v reflect.Value) error {
				p, null, err := d.readString(majorText)
				if err == nil && !null {
					v.SetString(string(p))
				}
				return err
			}
	case reflect.Pointer:
		elem := &lazyCodec{t: t.Elem()}
		return func(b []byte, v reflect.Value) ([]byte, error) {
				if v.IsNil() {
					return append(b, simpleNull), nil
				}
				return elem.get().enc(b, v.Elem())
			}, func(d *decoder, v reflect.Value) error {
				if d.null() {
					v.SetZero()
					return nil
				}
				if v.IsNil() {
					v.Set(reflect.New(t.Elem()))
				}
				return elem.get().dec(d, v.Elem())
			}
	case reflect.Interface:
		if t.NumMethod() != 0 {
			return unsupported(t)
		}
		return func(b []byte, v reflect.Value) ([]byte, error) {
				if v.IsNil() {
					return append(b, simpleNull), nil
				}
				e := v.Elem()
				return codecFor(e.Type()).enc(b, e)
			}, func(d *decoder, v reflect.Value) error {
				x, err := d.decodeAny(0)
				if err != nil {
					return err
				}
				if x == nil {
					v.SetZero()
				} else {
					v.Set(reflect.ValueOf(x))
				}
				return nil
			}
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 && !reflect.PointerTo(t.Elem()).Implements(marshalerType) {
			return func(b []byte, v reflect.Value) ([]byte, error) {
					if v.IsNil() {
						return append(b, simpleNull), nil
					}
					return appendString(b, majorBytes, string(v.Bytes())), nil
				}, func(d *decoder, v reflect.Value) error {
					p, null, err := d.readString(majorBytes)
					if err != nil {
						return err
					}
					if null {
						v.SetZero()
					} else {
						v.SetBytes(append([]byte{}, p...))
					}
					return nil
				}
		}
		elem := &lazyCodec{t: t.Elem()}
		return func(b []byte, v reflect.Value) ([]byte, error) {
				if v.IsNil() {
					return append(b, simpleNull), nil
				}
				n := v.Len()
				b = appendHead(b, majorArray, uint64(n))
				var err error
				for i := 0; i < n; i++ {
					if b, err = elem.get().enc(b, v.Index(i)); err != nil {
						return nil, err
					}
				}
				return b, nil
			}, func(d *decoder, v reflect.Value) error {
				n, null, err := d.readLength(majorArray)
				if err != nil {
					return err
				}
				if null {
					v.SetZero()
					return nil
				}
				s := reflect.MakeSlice(t, n, n)
				for i := 0; i < n; i++ {
					if err := elem.get().dec(d, s.Index(i)); err != nil {
						return err
					}
				}
				v.Set(s)
				return nil
			}
	case reflect.Map:
		switch t.Key().Kind() {
		case reflect.String,
			reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		default:
			return unsupported(t)
		}
		key := &lazyCodec{t: t.Key()}
		elem := &lazyCodec{t: t.Elem()}
		return func(b []byte, v reflect.Value) ([]byte, error) {
				if v.IsNil() {
					return append(b, simpleNull), nil
				}
				b = appendHead(b, majorMap, uint64(v.Len()))
				var err error
				for it := v.MapRange(); it.Next(); {
					if b, err = key.get().enc(b, it.Key()); err != nil {
						return nil, err
					}
					if b, err = elem.get().enc(b, it.Value()); err != nil {
						return nil, err
					}
				}
				return b, nil
			}, func(d *decoder, v reflect.Value) error {
				n, null, err := d.readLength(majorMap)
				if err != nil {
					return err
				}
				if null {
					v.SetZero()
					return nil
				}
				if v.IsNil() {
					v.Set(reflect.MakeMapWithSize(t, n))
				}
				k, e := reflect.New(t.Key()).Elem(), reflect.New(t.Elem()).Elem()
				for i := 0; i < n; i++ {
					k.SetZero()
					e.SetZero()
					if err := key.get().dec(d, k); err != nil {
						return err
					}
					if err := elem.get().dec(d, e); err != nil {
						return err
					}
					v.SetMapIndex(k, e)
				}
				return nil
			}
	case reflect.Struct:
		return structCodec(t)
	}
	return unsupported(t)
}

func mismatch(major byte, t reflect.Type) error {
	return fmt.Errorf("cbor: cannot decode major type %d into %v", major, t)
}

// field is a struct field, possibly promoted from an embedded struct.
type field struct {
	name      string
	index     []int
	tagged    bool
	omitEmpty bool
	c         lazyCodec
}

// structFields returns the fields of t that encoding/json would encode, in
// the order in which encoding/json would encode them.
func structFields(t reflect.Type) ([]field, error) {
	fields := make([]field, 0, t.NumField())
	embedded := false
	var walk func(t reflect.Type, index []int) error
	walk = func(t reflect.Type, index []int) error {
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag := f.Tag.Get("json")
			if tag == "-" {
				continue
			}
			name, opts, _ := strings.Cut(tag, ",")
			if f.Anonymous && name == "" {
				if f.Type.Kind() == reflect.Pointer {
					return fmt.Errorf("cbor: embedded pointer %v in %v is not supported", f.Type, t)
				}
				if f.Type.Kind() == reflect.Struct {
					embedded = true
					if err := walk(f.Type, append(index[:len(index):len(index)], i)); err != nil {
						return err
					}
					continue
				}
			}
			if !f.IsExported() {
				continue
			}
			tagged := name != ""
			if !tagged {
				name = f.Name
			}
			fields = append(fields, field{
				name:      name,
				index:     append(index[:len(index):len(index)], i),
				tagged:    tagged,
				omitEmpty: opts == "omitempty" || strings.Contains(","+opts+",", ",omitempty,"),
				c:         lazyCodec{t: f.Type},
			})
		}
		return nil
	}
	if err := walk(t, nil); err != nil {
		return nil, err
	}
	if !embedded && !hasDuplicateNames(fields) {
		return fields, nil
	}
	// Resolve name conflicts like encoding/json: the shallowest field wins; at
	// the same depth, a tagged field wins over untagged ones; otherwise all
	// conflicting fields are dropped.
	var resolved []field
	for i := range fields {
		f := &fields[i]
		keep := true
		for j := range fields {
			g := &fields[j]
			if i == j || g.name != f.name {
				continue
			}
			if len(g.index) < len(f.index) || (len(g.index) == len(f.index) && (g.tagged || !f.tagged)) {
				keep = false
				break
			}
		}
		if keep {
			resolved = append(resolved, field{name: f.name, index: f.index, tagged: f.tagged, omitEmpty: f.omitEmpty, c: lazyCodec{t: f.c.t}})
		}
	}
	return resolved, nil
}

func hasDuplicateNames(fields []field) bool {
	for i := range fields {
		for j := i + 1; j < len(fields); j++ {
			if fields[i].name == fields[j].name {
				return true
			}
		}
	}
	return false
}

func structCodec(t reflect.Type) (encFn, decFn) {
	fields, err := structFields(t)
	if err != nil {
		return func([]byte, reflect.Value) ([]byte, error) { return nil, err },
			func(*decoder, reflect.Value) error { return err }
	}
	fieldValue := func(v reflect.Value, f *field) reflect.Value {
		if len(f.index) == 1 {
			return v.Field(f.index[0])
		}
		return v.FieldByIndex(f.index)
	}
	return func(b []byte, v reflect.Value) ([]byte, error) {
			n := 0
			for i := range fields {
				if !fields[i].omitEmpty || !isEmpty(fieldValue(v, &fields[i])) {
					n++
				}
			}
			b = appendHead(b, majorMap, uint64(n))
			var err error
			for i := range fields {
				f := &fields[i]
				fv := fieldValue(v, f)
				if f.omitEmpty && isEmpty(fv) {
					continue
				}
				b = appendString(b, majorText, f.name)
				if b, err = f.c.get().enc(b, fv); err != nil {
					return nil, err
				}
			}
			return b, nil
		}, func(d *decoder, v reflect.Value) error {
			n, null, err := d.readLength(majorMap)
			if err != nil || null {
				return err
			}
			next := 0 // Fields are usually encoded in order.
			for i := 0; i < n; i++ {
				name, null, err := d.readString(majorText)
				if err != nil {
					return err
				}
				if null {
					return fmt.Errorf("cbor: null key in map for %v", t)
				}
				f := -1
				for j := range fields {
					if k := (next + j) % len(fields); fields[k].name == string(name) {
						f = k
						break
					}
				}
				if f < 0 {
					if err := d.skip(0); err != nil {
						return err
					}
					continue
				}
				next = f + 1
				if err := fields[f].c.get().dec(d, fieldValue(v, &fields[f])); err != nil {
					return err
				}
			}
			return nil
		}
}

// isEmpty returns true if v is empty for `json:",omitempty"`.
func isEmpty(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Map, reflect.Slice, reflect.String:
		return v.Len() == 0
	case reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64,
		reflect.Interface, reflect.Pointer:
		return v.IsZero()
	}
	return false
}

func marshalerCodec() (encFn, decFn) {
	return func(b []byte, v reflect.Value) ([]byte, error) {
			if !v.CanAddr() {
				// Not reachable through a pointer: copy it.
				p := reflect.New(v.Type())
				p.Elem().Set(v)
				v = p.Elem()
			}
			p, err := v.Addr().Interface().(Marshaler).MarshalCBOR()
			if err != nil {
				return nil, err
			}
			return append(b, p...), nil
		}, func(d *decoder, v reflect.Value) error {
			start := d.buf
			if err := d.skip(0); err != nil {
				return err
			}
			return v.Addr().Interface().(Unmarshaler).UnmarshalCBOR(start[:len(start)-len(d.buf)])
		}
}

func timeCodec() (encFn, decFn) {
	return func(b []byte, v reflect.Value) ([]byte, error) {
			t := v.Interface().(time.Time)
			return appendString(b, majorText, t.Format(time.RFC3339Nano)), nil
		}, func(d *decoder, v reflect.Value) error {
			p, null, err := d.readString(majorText)
			if err != nil || null {
				return err
			}
			t, err := time.Parse(time.RFC3339Nano, string(p))
			if err != nil {
				return fmt.Errorf("cbor: %w", err)
			}
			v.Set(reflect.ValueOf(t))
			return nil
		}
}

// appendHead appends the head of a data item: the major type and its
// argument, in the shortest form.
func appendHead(b []byte, major byte, arg uint64) []byte {
	m := major << 5
	switch {
	case arg < 24:
		return append(b, m|byte(arg))
	case arg <= math.MaxUint8:
		return append(b, m|24, byte(arg))
	case arg <= math.MaxUint16:
		return binary.BigEndian.AppendUint16(append(b, m|25), uint16(arg))
	case arg <= math.MaxUint32:
		return binary.BigEndian.AppendUint32(append(b, m|26), uint32(arg))
	default:
		return binary.BigEndian.AppendUint64(append(b, m|27), arg)
	}
}

func appendInt(b []byte, x int64) []byte {
	if x < 0 {
		return appendHead(b, majorNegInt, uint64(-1-x))
	}
	return appendHead(b, majorUint, uint64(x))
}

func appendString(b []byte, major byte, s string) []byte {
	return append(appendHead(b, major, uint64(len(s))), s...)
}

type decoder struct {
	buf []byte
}

func (d *decoder) readByte() (byte, error) {
	if len(d.buf) == 0 {
		return 0, errShort
	}
	x := d.buf[0]
	d.buf = d.buf[1:]
	return x, nil
}

// null consumes a null data item and returns true, or returns false.
func (d *decoder) null() bool {
	if len(d.buf) > 0 && d.buf[0] == simpleNull {
		d.buf = d.buf[1:]
		return true
	}
	return false
}

// readHead reads the head of a data item. For floats, arg holds their bits.
// null is true for a null data item.
func (d *decoder) readHead() (major byte, arg uint64, null bool, err error) {
	ib, err := d.readByte()
	if err != nil {
		return 0, 0, false, err
	}
	if ib == simpleNull {
		return majorSimple, 0, true, nil
	}
	major, ai := ib>>5, ib&0x1f
	n := 0
	switch {
	case ai < 24:
		return major, uint64(ai), false, nil
	case ai == 24:
		n = 1
	case ai == 25:
		n = 2
	case ai == 26:
		n = 4
	case ai == 27:
		n = 8
	default:
		return 0, 0, false, fmt.Errorf("cbor: unsupported initial byte %#x", ib)
	}
	if len(d.buf) < n {
		return 0, 0, false, errShort
	}
	for _, x := range d.buf[:n] {
		arg = arg<<8 | uint64(x)
	}
	d.buf = d.buf[n:]
	return major, arg, false, nil
}

// readLength reads the head of an array or map and returns its length,
// bounded by the remaining data.
func (d *decoder) readLength(major byte) (int, bool, error) {
	m, arg, null, err := d.readHead()
	if err != nil || null {
		return 0, null, err
	}
	if m != major {
		return 0, false, fmt.Errorf("cbor: got major type %d, want %d", m, major)
	}
	// Each element takes at least one byte.
	if arg > uint64(len(d.buf)) {
		return 0, false, errShort
	}
	return int(arg), false, nil
}

// readString reads a byte string or text string, without copying it.
func (d *decoder) readString(major byte) ([]byte, bool, error) {
	m, arg, null, err := d.readHead()
	if err != nil || null {
		return nil, null, err
	}
	if m != major {
		return nil, false, fmt.Errorf("cbor: got major type %d, want %d", m, major)
	}
	if arg > uint64(len(d.buf)) {
		return nil, false, errShort
	}
	p := d.buf[:arg]
	d.buf = d.buf[arg:]
	return p, false, nil
}

func (d *decoder) readFloat() (float64, bool, error) {
	if len(d.buf) == 0 {
		return 0, false, errShort
	}
	ib := d.buf[0]
	major, arg, null, err := d.readHead()
	switch {
	case err != nil || null:
		return 0, null, err
	case ib == simpleFloat64:
		return math.Float64frombits(arg), false, nil
	case ib == simpleFloat32:
		return float64(math.Float32frombits(uint32(arg))), false, nil
	case major == majorUint:
		return float64(arg), false, nil
	case major == majorNegInt:
		return -1 - float64(arg), false, nil
	}
	return 0, false, fmt.Errorf("cbor: cannot decode %#x as a float", ib)
}

// readKey reads a map key as encoding/json represents it: integer keys are
// converted to strings.
func (d *decoder) readKey() (string, error) {
	if len(d.buf) == 0 {
		return "", errShort
	}
	switch d.buf[0] >> 5 {
	case majorText:
		p, _, err := d.readString(majorText)
		return string(p), err
	case majorUint, majorNegInt:
		major, arg, _, err := d.readHead()
		if err != nil {
			return "", err
		}
		if major == majorUint {
			return strconv.FormatUint(arg, 10), nil
		}
		if arg > math.MaxInt64 {
			return "", fmt.Errorf("cbor: map key overflows int64")
		}
		return strconv.FormatInt(-1-int64(arg), 10), nil
	}
	return "", fmt.Errorf("cbor: unsupported map key %#x", d.buf[0])
}

// skip skips a data item.
func (d *decoder) skip(depth int) error {
	if depth > maxDepth {
		return errors.New("cbor: data nested too deeply")
	}
	major, arg, _, err := d.readHead()
	if err != nil {
		return err
	}
	switch major {
	case majorBytes, majorText:
		if arg > uint64(len(d.buf)) {
			return errShort
		}
		d.buf = d.buf[arg:]
	case majorArray, majorMap:
		if arg > uint64(len(d.buf)) {
			return errShort
		}
		n := int(arg)
		if major == majorMap {
			n *= 2
		}
		for i := 0; i < n; i++ {
			if err := d.skip(depth + 1); err != nil {
				return err
			}
		}
	case majorTag:
		return d.skip(depth + 1)
	}
	return nil
}

// decodeAny decodes a data item into the value that encoding/json would
// decode the equivalent JSON into: nil, bool, float64, string, []any or
// map[string]any.
func (d *decoder) decodeAny(depth int) (any, error) {
	if depth > maxDepth {
		return nil, errors.New("cbor: data nested too deeply")
	}
	if len(d.buf) == 0 {
		return nil, errShort
	}
	switch ib := d.buf[0]; {
	case ib == simpleNull:
		d.buf = d.buf[1:]
		return nil, nil
	case ib == simpleTrue || ib == simpleFalse:
		d.buf = d.buf[1:]
		return ib == simpleTrue, nil
	case ib>>5 == majorUint || ib>>5 == majorNegInt || ib == simpleFloat32 || ib == simpleFloat64:
		x, _, err := d.readFloat()
		return x, err
	case ib>>5 == majorText:
		p, _, err := d.readString(majorText)
		return string(p), err
	case ib>>5 == majorArray:
		n, _, err := d.readLength(majorArray)
		if err != nil {
			return nil, err
		}
		s := make([]any, n)
		for i := range s {
			if s[i], err = d.decodeAny(depth + 1); err != nil {
				return nil, err
			}
		}
		return s, nil
	case ib>>5 == majorMap:
		n, _, err := d.readLength(majorMap)
		if err != nil {
			return nil, err
		}
		m := make(map[string]any, n)
		for i := 0; i < n; i++ {
			k, err := d.readKey()
			if err != nil {
				return nil, err
			}
			if m[k], err = d.decodeAny(depth + 1); err != nil {
				return nil, err
			}
		}
		return m, nil
	default:
		return nil, fmt.Errorf("cbor: unsupported initial byte %#x", ib)
	}
}
