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
	_{{.Name}} := (*C.char)(nil)
	if {{.Value}} != "" {
		_{{.Name}} = C.CString({{.Value}})
		defer C.free(unsafe.Pointer(_{{.Name}}))
	}
	{{else if eq "[]byte" (.GoType)}}
	_{{.Name}} := unsafe.Pointer(nil)
	if {{.Value}} != nil {
		_{{.Name}} = C.CBytes({{.Value}})
		defer C.free(_{{.Name}})
	}
	{{else}}
	_{{.Name}} := ({{.CType}})({{.Value}})
	{{end}}
	{{end}}
	
	ival := C.{{$.Ns}}_{{.Name}}(
		&arglist,
		d.cd,
		{{range .Params}}
		_{{.Name}},
		{{end}})
	
	err = newError(int(ival), logMessages(arglist))
	{{with .Return}}out = ({{.}})(ival){{end}}
	return
}
{{end}}
