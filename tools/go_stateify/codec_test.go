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

package main

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

const testSource = `package p

import "example.com/other"

type name uint16
type names []name
type byName map[string]*node
type alias = name
type shadowed struct{}
type pair [2]name
type foreign other.Thing
type foreignMap map[other.Key]int
type localIface interface{ f() }

// +stateify savable
type node struct {
	a     int32
	b, c  string
	n     name
	al    alias
	p     *node
	op    *other.Thing
	s     []*node
	ns    names
	arr   [4]byte
	pairs [3]pair
	m     map[name]*node
	bn    byName
	fm    foreignMap
	o     other.Thing
	f     foreign
	i     any
	li    localIface
	v     int ` + "`state:\".(int64)\"`" + `
	w     *node ` + "`state:\"wait\"`" + `
	skip  int ` + "`state:\"nosave\"`" + `
	z     int ` + "`state:\"zerovalue\"`" + `
	nested struct {
		x int
	}
}
`

func parseTestSource(t *testing.T) (*ast.File, *codecGen, *ast.StructType) {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "p.go", testSource, parser.ParseComments)
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	g := &codecGen{local: make(localTypes), statePrefix: "state."}
	var node *ast.StructType
	for _, decl := range f.Decls {
		if d, ok := decl.(*ast.GenDecl); ok && d.Tok == token.TYPE {
			for _, s := range d.Specs {
				ts := s.(*ast.TypeSpec)
				g.add(ts)
				if ts.Name.Name == "node" {
					node = ts.Type.(*ast.StructType)
				}
			}
		}
	}
	return f, g, node
}

func TestCollectFields(t *testing.T) {
	_, _, node := parseTestSource(t)
	var got []string
	for _, f := range collectFields(node) {
		got = append(got, f.name)
	}
	want := "a b c n al p op s ns arr pairs m bn fm o f i li v w x"
	if strings.Join(got, " ") != want {
		t.Errorf("fields: got %v, want %v", got, want)
	}
}

func TestFieldCalls(t *testing.T) {
	_, g, node := parseTestSource(t)
	calls := make(map[string][2]string)
	for _, f := range collectFields(node) {
		calls[f.name] = [2]string{g.fieldCall("x."+f.name, f.typ, false), g.fieldCall("x."+f.name, f.typ, true)}
	}
	for _, tc := range []struct {
		field, enc, dec string
	}{
		{"a", "state.EncodeInt(stateEncoder, &x.a)", "state.DecodeInt(stateDecoder, &x.a)"},
		{"b", "state.EncodeString(stateEncoder, &x.b)", "state.DecodeString(stateDecoder, &x.b)"},
		{"n", "state.EncodeUint(stateEncoder, &x.n)", "state.DecodeUint(stateDecoder, &x.n)"},
		{"al", "state.EncodeUint(stateEncoder, &x.al)", ""},
		{"p", "state.EncodePointer(stateEncoder, &x.p)", "state.DecodePointer(stateDecoder, &x.p)"},
		{"op", "state.EncodePointer(stateEncoder, &x.op)", ""},
		{"s", "state.EncodeSlice(stateEncoder, &x.s, state.EncodePointer)", "state.DecodeSlice(stateDecoder, &x.s, state.DecodePointer)"},
		{"ns", "state.EncodeSlice(stateEncoder, &x.ns, state.EncodeUint)", ""},
		{"arr", "state.EncodeArray(stateEncoder, x.arr[:], state.EncodeUint)", "state.DecodeArray(stateDecoder, x.arr[:], state.DecodeUint)"},
		{"pairs", "state.EncodeArray(stateEncoder, x.pairs[:], func(e *state.Encoder, p *pair) { state.EncodeArray(e, p[:], state.EncodeUint) })", ""},
		{"m", "state.EncodeMap(stateEncoder, &x.m, state.EncodeUint, state.EncodePointer)", ""},
		{"bn", "state.EncodeMap(stateEncoder, &x.bn, state.EncodeString, state.EncodePointer)", ""},
		// Types from other packages are handled at run time.
		{"fm", "state.EncodeMap(stateEncoder, &x.fm, state.EncodeValue, state.EncodeInt)", ""},
		{"o", "state.EncodeAny(stateEncoder, &x.o)", "state.DecodeAny(stateDecoder, &x.o)"},
		{"f", "state.EncodeAny(stateEncoder, &x.f)", ""},
		{"i", "state.EncodeAny(stateEncoder, &x.i)", ""},
		{"li", "state.EncodeInterface(stateEncoder, &x.li)", "state.DecodeInterface(stateDecoder, &x.li)"},
		{"x", "state.EncodeInt(stateEncoder, &x.x)", ""},
	} {
		got, ok := calls[tc.field]
		if !ok {
			t.Errorf("field %s not found", tc.field)
			continue
		}
		if got[0] != tc.enc {
			t.Errorf("field %s: got encoder\n\t%s\nwant\n\t%s", tc.field, got[0], tc.enc)
		}
		if tc.dec != "" && got[1] != tc.dec {
			t.Errorf("field %s: got decoder\n\t%s\nwant\n\t%s", tc.field, got[1], tc.dec)
		}
	}
}

func TestShadowedPrimitive(t *testing.T) {
	g := &codecGen{local: localTypes{"int": &ast.StructType{}}, statePrefix: "state."}
	if got, want := g.fieldCall("x.f", ast.NewIdent("int"), false), "state.EncodeAny(stateEncoder, &x.f)"; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestEmitCodec(t *testing.T) {
	_, g, node := parseTestSource(t)
	var buf bytes.Buffer
	buf.WriteString("package p\n\n")
	g.emitCodec(&buf, "x", "node", node, true, func() {
		buf.WriteString("\t// zero value checks\n")
	})
	out := buf.String()
	if _, err := parser.ParseFile(token.NewFileSet(), "out.go", out, 0); err != nil {
		t.Fatalf("generated code does not parse: %v\n%s", err, out)
	}
	for _, want := range []string{
		"var stateTypeIndexnode state.TypeIndex",
		"func (x *node) StateTypeIndex() *state.TypeIndex {",
		// Values are saved first, as by StateSave, and encoded in slot order.
		"x.beforeSave()\n\t// zero value checks\n\tvValue := x.saveV()\n\t_ = (int64)(vValue)\n\tstate.EncodeInt(stateEncoder, &x.a)",
		"state.EncodeInt(stateEncoder, &vValue)\n\tstate.EncodePointer(stateEncoder, &x.w)",
		// Values are decoded in slot order, and loaded last, as by StateLoad.
		"var vValue int64\n\tstateDecoder.BeginWait()\n\tstate.DecodeInt(stateDecoder, &vValue)\n\tvRef := stateDecoder.EndValue()\n\tstateDecoder.BeginWait()\n\tstate.DecodePointer(stateDecoder, &x.w)\n\tstateDecoder.EndWait()",
		"if stateDecoder.LoadValueNow(vRef) {\n\t\tx.loadV(ctx, vValue)\n\t} else {\n\t\tstateDecoder.LoadValueLater(vRef, x, 18, vValue)\n\t}\n\tstateDecoder.AfterLoad(x)\n}",
		"func (x *node) StateLoadValue(ctx context.Context, stateField int, stateValue any) {\n\tswitch stateField {\n\tcase 18:\n\t\tstateV, _ := stateValue.(int64)\n\t\tx.loadV(ctx, stateV)\n\t}\n}",
		"func (x *node) StateAfterLoad(ctx context.Context) {\n\tx.afterLoad(ctx)\n}",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("generated code does not contain\n%s\n\ngenerated code:\n%s", want, out)
		}
	}
}
