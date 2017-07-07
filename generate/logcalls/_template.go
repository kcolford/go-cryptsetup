{{/* -*- mode: go; gofmt-show-errors: nil; -*- */}}
package {{$.PackageName}}

// #cgo pkg-config: libcryptsetup
// #include <libcryptsetup.h>
// #include <stdlib.h>
// #include "{{$.FileName "h"}}"
// #include "log.h"
import "C"
import (
	"unsafe"
)

{{range .Methods}}
func (d Device) {{.GoName}}({{range $k, $v := .DeclParams}}{{if $k}}, {{end}}{{$v.Name}} {{$v.GoType}}{{end}}) ({{with .Return}}out {{.}}, {{end}}err error) {
	arglist := (*C.struct_gocrypt_logstack)(nil)
	{{range .Params}}
	{{if eq "string" (.GoType)}}
	_{{.Name}} := cString({{.Value}})
	defer cStringFree(_{{.Name}})
	{{else if eq "[]byte" (.GoType)}}
	_{{.Name}} := cBytes({{.Value}})
	defer cBytesFree(_{{.Name}})
	{{else}}
	_{{.Name}} := ({{.CType}})({{.Value}})
	{{end}}
	{{end}}
	
	ival := C.{{$.Ns}}_{{.Name}}(
		&arglist,
		d.cd,
		{{range .Params}}
		_{{.Name}},
		{{end}}
	)
	
	err = newError(int(ival), logMessages(arglist))
	{{with .Return}}out = ({{.}})(ival){{end}}
	return
}
{{end}}
