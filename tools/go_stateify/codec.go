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
	"fmt"
	"go/ast"
	"go/parser"
	"go/types"
	"io"
	"strings"
)

// This file generates the typed StateEncode and StateDecode methods (see
// state.Codec).
//
// go_stateify only parses the package's own sources, so the kind of a type
// is known only for predeclared types, composite type literals and types
// declared in the package. Fields of other types are encoded and decoded by
// state.EncodeValue and state.DecodeValue, which dispatch on the type's kind
// at run time (calling the type's own StateEncode/StateDecode for structs).

// fieldKind is the kind of a saved field.
type fieldKind int

const (
	fieldNormal fieldKind = iota
	fieldWait
	fieldValue
)

// fieldInfo describes a saved field, in slot order.
type fieldInfo struct {
	name string
	typ  ast.Expr
	kind fieldKind
	// valueType is the type of the value for fieldValue.
	valueType string
}

// collectFields returns the saved fields of ss in slot order. It mirrors
// scanFields.
func collectFields(ss *ast.StructType) []fieldInfo {
	var fields []fieldInfo
	if ss.Fields.List == nil {
		return nil
	}
	for _, field := range ss.Fields.List {
		names := []string{}
		if field.Names == nil {
			name, _ := resolveTypeName(field.Type)
			names = append(names, name)
		} else {
			for _, n := range field.Names {
				if n.Name != "_" {
					names = append(names, n.Name)
				}
			}
		}
		for _, name := range names {
			tag := extractStateTag(field.Tag)
			if anon, ok := field.Type.(*ast.StructType); ok && tag == "" {
				fields = append(fields, collectFields(anon)...)
				continue
			}
			switch {
			case tag == "":
				fields = append(fields, fieldInfo{name: name, typ: field.Type, kind: fieldNormal})
			case tag == "wait":
				fields = append(fields, fieldInfo{name: name, typ: field.Type, kind: fieldWait})
			case strings.HasPrefix(tag, ".(") && strings.HasSuffix(tag, ")"):
				fields = append(fields, fieldInfo{name: name, typ: field.Type, kind: fieldValue, valueType: tag[2 : len(tag)-1]})
			}
		}
	}
	return fields
}

// add records a type declaration.
func (g *codecGen) add(ts *ast.TypeSpec) {
	g.local.add(ts)
}

// localTypes maps the names of types declared in the package to their
// definitions. Names with conflicting definitions (e.g. in files for
// different architectures) map to nil.
type localTypes map[string]ast.Expr

// add records a type declaration.
func (lt localTypes) add(ts *ast.TypeSpec) {
	if ts.TypeParams != nil {
		lt[ts.Name.Name] = nil
		return
	}
	if prev, ok := lt[ts.Name.Name]; ok && types.ExprString(prev) != types.ExprString(ts.Type) {
		lt[ts.Name.Name] = nil
		return
	}
	lt[ts.Name.Name] = ts.Type
}

// primitive returns the state package's encoding function suffix for a
// predeclared type, or "" if name is not a supported predeclared type.
func primitive(name string) string {
	switch name {
	case "bool":
		return "Bool"
	case "int", "int8", "int16", "int32", "int64", "rune":
		return "Int"
	case "uint", "uint8", "uint16", "uint32", "uint64", "uintptr", "byte":
		return "Uint"
	case "float32":
		return "Float32"
	case "float64":
		return "Float64"
	case "complex64":
		return "Complex64"
	case "complex128":
		return "Complex128"
	case "string":
		return "String"
	}
	return ""
}

// codecGen generates codec methods.
type codecGen struct {
	local localTypes
	// statePrefix is the state package qualifier, e.g. "state.".
	statePrefix string
}

// underlying resolves local named types (through local aliases and
// definitions) to a type literal or predeclared type. It returns nil if t
// cannot be resolved.
func (g *codecGen) underlying(t ast.Expr) ast.Expr {
	for i := 0; i < 16; i++ {
		switch x := t.(type) {
		case *ast.ParenExpr:
			t = x.X
		case *ast.Ident:
			if primitive(x.Name) != "" {
				if _, shadowed := g.local[x.Name]; shadowed {
					return nil
				}
				return x
			}
			def, ok := g.local[x.Name]
			if !ok || def == nil {
				return nil
			}
			t = def
		default:
			return t
		}
	}
	return nil
}

// printable returns true if t can be written in the generated file: it must
// not refer to other packages (which may not be imported).
func printable(t ast.Expr) bool {
	ok := true
	ast.Inspect(t, func(n ast.Node) bool {
		switch n.(type) {
		case *ast.SelectorExpr, *ast.StructType, *ast.InterfaceType, *ast.FuncType, *ast.ChanType, *ast.IndexExpr, *ast.IndexListExpr:
			ok = false
		}
		return ok
	})
	return ok
}

// kind classifies t for code generation, returning the resolved type.
func (g *codecGen) kind(t ast.Expr) (string, ast.Expr) {
	u := g.underlying(t)
	switch x := u.(type) {
	case *ast.Ident:
		return primitive(x.Name), x
	case *ast.StarExpr:
		return "Pointer", x
	case *ast.ArrayType:
		if x.Len == nil {
			return "Slice", x
		}
		if _, ok := x.Len.(*ast.Ellipsis); ok {
			return "", nil
		}
		return "Array", x
	case *ast.MapType:
		return "Map", x
	case *ast.InterfaceType:
		return "Interface", x
	}
	return "", nil
}

// elemFunc returns an expression for a function encoding (or decoding, if dec)
// values of type t, with the signature of state.EncodeValue[T] (or
// state.DecodeValue[T]). Type arguments are inferred where it is used.
func (g *codecGen) elemFunc(t ast.Expr, dec bool) string {
	sp := g.statePrefix
	op := "Encode"
	if dec {
		op = "Decode"
	}
	k, _ := g.kind(t)
	switch k {
	case "":
		return sp + op + "Value"
	case "Slice", "Array", "Map":
		if !printable(t) {
			// The function literal below would need to name t.
			return sp + op + "Value"
		}
		params := fmt.Sprintf("e *%sEncoder, p *%s, m %sMode", sp, types.ExprString(t), sp)
		if dec {
			params = fmt.Sprintf("d *%sDecoder, p *%s, tag %sTag", sp, types.ExprString(t), sp)
		}
		return fmt.Sprintf("func(%s) { %s }", params, g.call("p", t, dec, true))
	default:
		return sp + op + k
	}
}

// call returns a call encoding (or decoding, if dec) the value of type t
// pointed to by ptr. If elem, the call is in a function returned by elemFunc
// (with parameters e, p and m, or d, p and tag); otherwise it is in
// StateEncode (or StateDecode).
func (g *codecGen) call(ptr string, t ast.Expr, dec, elem bool) string {
	sp := g.statePrefix
	op, v, arg := "Encode", "stateEncoder", sp+"ModeDefault"
	if dec {
		op, v, arg = "Decode", "stateDecoder", "stateDecoder.Tag()"
	}
	return g.callWith(ptr, t, dec, elem, op, v, arg)
}

// callWith is call, with the given encoder (or decoder) variable v and mode
// (or tag) argument.
func (g *codecGen) callWith(ptr string, t ast.Expr, dec, elem bool, op, v, arg string) string {
	sp := g.statePrefix
	if elem {
		v, arg = "e", "m"
		if dec {
			v, arg = "d", "tag"
		}
	}
	k, u := g.kind(t)
	switch k {
	case "":
		if !elem {
			// Avoid instantiating EncodeValue for each field type.
			return fmt.Sprintf("%s%sAny(%s, %s, %s)", sp, op, v, ptr, arg)
		}
		return fmt.Sprintf("%s%sValue(%s, %s, %s)", sp, op, v, ptr, arg)
	case "Slice":
		return fmt.Sprintf("%s%sSlice(%s, %s, %s, %s)", sp, op, v, ptr, arg, g.elemFunc(u.(*ast.ArrayType).Elt, dec))
	case "Array":
		return fmt.Sprintf("%s%sArray(%s, %s[:], %s, %s)", sp, op, v, strings.TrimPrefix(ptr, "&"), arg, g.elemFunc(u.(*ast.ArrayType).Elt, dec))
	case "Map":
		mt := u.(*ast.MapType)
		return fmt.Sprintf("%s%sMap(%s, %s, %s, %s, %s)", sp, op, v, ptr, arg, g.elemFunc(mt.Key, dec), g.elemFunc(mt.Value, dec))
	default:
		return fmt.Sprintf("%s%s%s(%s, %s, %s)", sp, op, k, v, ptr, arg)
	}
}

// fieldCall returns a statement encoding (or decoding) the field expr of type
// t.
func (g *codecGen) fieldCall(expr string, t ast.Expr, dec bool) string {
	return g.call("&"+expr, t, dec, false)
}

// emitCodec emits the Codec methods of struct type name.
func (g *codecGen) emitCodec(w io.Writer, recv, name string, ss *ast.StructType, hasAfterLoad bool, emitZeroChecks func()) {
	sp := g.statePrefix
	fields := collectFields(ss)
	idx := "stateTypeIndex" + name

	fmt.Fprintf(w, "var %s %sTypeIndex\n\n", idx, sp)
	fmt.Fprintf(w, "func (%s *%s) StateTypeIndex() *%sTypeIndex {\n", recv, name, sp)
	fmt.Fprintf(w, "	return &%s\n", idx)
	fmt.Fprintf(w, "}\n\n")

	// StateEncode: see StateSave for the order of side effects.
	fmt.Fprintf(w, "// +checklocksignore\n")
	fmt.Fprintf(w, "func (%s *%s) StateEncode(stateEncoder *%sEncoder) {\n", recv, name, sp)
	fmt.Fprintf(w, "	%s.beforeSave()\n", recv)
	emitZeroChecks()
	for _, f := range fields {
		if f.kind == fieldValue {
			fmt.Fprintf(w, "	%sValue := %s.save%s()\n", f.name, recv, camelCased(f.name))
			fmt.Fprintf(w, "	_ = (%s)(%sValue)\n", f.valueType, f.name)
			vt, err := parser.ParseExpr(f.valueType)
			if err != nil {
				fmt.Fprintf(w, "	%sEncoded := %sEncodeLegacyValue(stateEncoder, %sValue)\n", f.name, sp, f.name)
				continue
			}
			enc := f.name + "ValueEncoder"
			fmt.Fprintf(w, "	%s := stateEncoder.Detach()\n", enc)
			fmt.Fprintf(w, "	%s\n", g.callWith("&"+f.name+"Value", vt, false, false, "Encode", enc, sp+"ModeDefault"))
			fmt.Fprintf(w, "	%sEncoded := %s.Finish()\n", f.name, enc)
		}
	}
	for _, f := range fields {
		if f.kind == fieldValue {
			fmt.Fprintf(w, "	%sEmbedValue(stateEncoder, %sEncoded)\n", sp, f.name)
			continue
		}
		fmt.Fprintf(w, "	%s\n", g.fieldCall(recv+"."+f.name, f.typ, false))
	}
	fmt.Fprintf(w, "}\n\n")

	fmt.Fprintf(w, "// +checklocksignore\n")
	fmt.Fprintf(w, "func (%s *%s) StateDecode(ctx context.Context, stateDecoder *%sDecoder) {\n", recv, name, sp)
	for _, f := range fields {
		switch f.kind {
		case fieldValue:
			fmt.Fprintf(w, "	%sEncoded := stateDecoder.LoadEncoded()\n", f.name)
		case fieldWait:
			fmt.Fprintf(w, "	stateDecoder.BeginWait()\n")
			fmt.Fprintf(w, "	%s\n", g.fieldCall(recv+"."+f.name, f.typ, true))
			fmt.Fprintf(w, "	stateDecoder.EndWait()\n")
		default:
			fmt.Fprintf(w, "	%s\n", g.fieldCall(recv+"."+f.name, f.typ, true))
		}
	}
	for _, f := range fields {
		if f.kind == fieldValue {
			fmt.Fprintf(w, "	stateDecoder.LoadValue(%sEncoded, new(%s), func(y any) { %s.load%s(ctx, y.(%s)) })\n", f.name, f.valueType, recv, camelCased(f.name), f.valueType)
		}
	}
	if hasAfterLoad {
		fmt.Fprintf(w, "	stateDecoder.AfterLoad(func() { %s.afterLoad(ctx) })\n", recv)
	}
	fmt.Fprintf(w, "}\n\n")
}

// emitIdentCodec emits the Codec methods of a type identical to typeName.
func (g *codecGen) emitIdentCodec(w io.Writer, recv, name, typeName string) {
	sp := g.statePrefix
	idx := "stateTypeIndex" + name
	fmt.Fprintf(w, "var %s %sTypeIndex\n\n", idx, sp)
	fmt.Fprintf(w, "func (%s *%s) StateTypeIndex() *%sTypeIndex {\n", recv, name, sp)
	fmt.Fprintf(w, "	return &%s\n", idx)
	fmt.Fprintf(w, "}\n\n")
	fmt.Fprintf(w, "// +checklocksignore\n")
	fmt.Fprintf(w, "func (%s *%s) StateEncode(stateEncoder *%sEncoder) {\n", recv, name, sp)
	fmt.Fprintf(w, "	(*%s)(%s).StateEncode(stateEncoder)\n", typeName, recv)
	fmt.Fprintf(w, "}\n\n")
	fmt.Fprintf(w, "// +checklocksignore\n")
	fmt.Fprintf(w, "func (%s *%s) StateDecode(ctx context.Context, stateDecoder *%sDecoder) {\n", recv, name, sp)
	fmt.Fprintf(w, "	(*%s)(%s).StateDecode(ctx, stateDecoder)\n", typeName, recv)
	fmt.Fprintf(w, "}\n\n")
}
