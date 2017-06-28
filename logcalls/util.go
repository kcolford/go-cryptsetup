package main

import "strings"

// GoName returns a Go function name that will be mapped to the C
// method.
func (m Method) GoName() string {
	s := strings.Split(m.Name, "_")
	s = s[1:]
	for k := range s {
		s[k] = strings.Title(s[k])
	}
	s[0] = strings.ToLower(s[0])
	return strings.Join(s, "")
}

// DeclParams returns a slice of all the MethodParams that will
// actually be exposed to the Go code.
func (m Method) DeclParams() []MethodParam {
	out := make([]MethodParam, 0, len(m.Params))
	for _, p := range m.Params {
		if p.ForceArg == "" {
			out = append(out, p)
		}
	}
	return out
}

// Value returns the value that will be passed to the C glue function
// from the Go code.
func (p MethodParam) Value() string {
	if p.ForceArg != "" {
		return p.ForceArg
	}
	return p.Name
}

// CType returns the Go mapping of the C datatype for a method
// parameter.
func (p MethodParam) CType() string {
	s := p.Type

	// remove qualifiers
	s = strings.TrimPrefix(s, "const")

	// add C. prefix
	s = strings.TrimSpace(s)
	s = "C." + s

	// fix pointer position
	starindex := strings.Index(s, "*")
	if starindex >= 0 {
		s = s[starindex:] + s[:starindex]
	}

	// convert spaces to underscores
	s = strings.TrimSpace(s)
	s = strings.Replace(s, " ", "_", -1)

	return s
}

// GoType returns the Go type used for the parameter.
func (p MethodParam) GoType() string {
	switch strings.TrimPrefix(p.Type, "const ") {
	case "char *":
		return "string"
	case "void *":
		return "[]byte"
	case "bool":
		fallthrough
	case "int":
		return p.Type
	default:
		return p.CType()
	}
}

// FileName returns the name of the file with the specified extension.
func (d Data) FileName(ext string) string {
	return d.BaseName + "." + ext
}

// HeaderGuard returns the macro name to be used in the header file's
// header-guard.
func (d Data) HeaderGuard() string {
	return strings.Replace(strings.ToUpper(d.FileName("h")), ".", "_", -1)
}
