// Generate crypt_* wrappers that also setup the log function for
// proper error reporting.

package main

import (
	"flag"
	"os"
	"path"
	"strings"
	"text/template"
	"time"
)

// MethodParam is a parameter of a method
type MethodParam struct {
	// the C type of the parameter, to be converted automatically
	// to corresponding Go types
	Type string

	// the name of the parameter in the function
	Name string

	// pass this Go code as the argument to the C function
	ForceArg string

	// this parameter is unsafe
	Unsafe bool
}

type Method struct {
	// the name of the method
	Name string

	// the parameters that the method takes, it is assumed that a
	// `struct crypt_device *cd` will be the first parameter (and
	// a logging handle before that on the glue bindings).
	Params []MethodParam

	// all functions are assumed to return an error condition
	// (negative errno) but sometimes they return a meaningful
	// result too. this is the type of that meaningful result
	Return string
}

type Field struct {
	Type string
	Name string
}

type Structure struct {
	Name   string
	Fields []Field
}

type Data struct {
	Methods     []Method
	Now         string
	Ns          string
	PackageName string
	BaseName    string
	Dir         string
}

func init() {
	flag.StringVar(&data.Now, "at", time.Now().String(), "the time to record the files were generated at")
	flag.StringVar(&data.Ns, "ns", "gocrypt", "the namespace in which generated C functions will live")
	pkg, ok := os.LookupEnv("GOPACKAGE")
	if !ok {
		pkg = "main"
	}
	flag.StringVar(&data.PackageName, "pkg", pkg, "the package name for the Go stub")
	flag.StringVar(&data.BaseName, "base", "logcalls", "the basename of the files that will be generated")
	flag.StringVar(&data.Dir, "d", ".", "the directory where templates are")
}

var data = Data{
	Methods: []Method{
		// formatting
		{Name: "crypt_format", Params: []MethodParam{
			{Type: "const char *", Name: "format"},
			{Type: "const char *", Name: "cipher"},
			{Type: "const char *", Name: "cipher_mode"},
			{Type: "const char *", Name: "uuid"},

			// XXX: note that we don't force this argument
			// because volume_key can be nil (NULL) and we
			// specify a length that will be generated,
			// care must be taken that the []byte slice
			// passed to volume_key matches the size
			// passed to volume_key_size if volume_key is
			// not nil
			{Type: "void *", Name: "volume_key"},
			{Type: "size_t", Name: "volume_key_size"},

			// this can be a pointer to any of a number of
			// types, therefore it must be managed as an
			// unsafe pointer
			{Type: "void *", Name: "params",
				Unsafe: true},
		}},
		{Name: "crypt_load", Params: []MethodParam{
			{Type: "const char *", Name: "requested_type"},
			{Type: "void *", Name: "params",
				Unsafe: true},
		}},

		// misc
		{Name: "crypt_get_rng_type", Return: "int"},
		{Name: "crypt_set_uuid", Params: []MethodParam{
			{Type: "const char *", Name: "uuid"},
		}},

		// keyslot managment
		{Name: "crypt_keyslot_add_by_passphrase", Params: []MethodParam{
			{Type: "int", Name: "keyslot"},
			{Type: "void *", Name: "passphrase"},
			{Type: "size_t", Name: "passphrase_size",
				ForceArg: "len(passphrase)"},
			{Type: "void *", Name: "new_passphrase"},
			{Type: "size_t", Name: "new_passphrase_size",
				ForceArg: "len(new_passphrase)"},
		}, Return: "int"},
		{Name: "crypt_keyslot_destroy", Params: []MethodParam{
			{Type: "int", Name: "keyslot"},
		}},

		// device activation
		{Name: "crypt_activate_by_passphrase", Params: []MethodParam{
			{Type: "const char *", Name: "name"},
			{Type: "int", Name: "keyslot"},
			{Type: "void *", Name: "passphrase"},
			{Type: "size_t", Name: "passphrase_size",
				ForceArg: "len(passphrase)"},
			{Type: "uint32_t", Name: "flags"},
		}, Return: "int"},
		{Name: "crypt_deactivate", Params: []MethodParam{
			{Type: "const char *", Name: "name"},
		}},

		// benchmarking
		{Name: "crypt_benchmark", Params: []MethodParam{
			{Type: "const char *", Name: "cipher"},
			{Type: "const char *", Name: "cipher_mode"},
			{Type: "size_t", Name: "volume_key_size"},
			{Type: "size_t", Name: "iv_size"},
			{Type: "size_t", Name: "buffer_size"},
			{Type: "double *", Name: "encryption_mbs"},
			{Type: "double *", Name: "decryption_mbs"},
		}},
		{Name: "crypt_benchmark_kdf", Params: []MethodParam{
			{Type: "const char *", Name: "kdf"},
			{Type: "const char *", Name: "hash"},
			{Type: "void *", Name: "password"},
			{Type: "size_t", Name: "password_size",
				ForceArg: "len(password)"},
			{Type: "void *", Name: "salt"},
			{Type: "size_t", Name: "salt_size",
				ForceArg: "len(salt)"},
			{Type: "uint64_t *", Name: "iterations_sec"},
		}},
	},
}

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
	if p.Unsafe || p.Type == "void *" {
		return "unsafe.Pointer"
	}
	s := "C." + p.Type
	for s[len(s)-1] == '*' {
		s = "*" + s[:len(s)-1]
	}
	s = strings.TrimSpace(s)
	s = strings.Replace(s, " ", "_", -1)
	return s
}

// GoType returns the Go type used for the parameter.
func (p MethodParam) GoType() string {
	if p.Unsafe {
		return "unsafe.Pointer"
	}
	switch p.Type {
	case "const char *":
		return "string"
	case "void *":
		return "[]byte"
	case "size_t":
		return "uintptr"
	case "uint64_t":
		return "uint64"
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

func Templates(data Data) (*template.Template, error) {
	return template.ParseGlob(path.Join(data.Dir, "_template.*"))
}

func Run(data Data) error {
	tmpl, err := Templates(data)
	if err != nil {
		return err
	}

	for _, ext := range []string{"h", "c", "go"} {
		f, err := os.Create(data.FileName(ext))
		if err != nil {
			return err
		}
		defer f.Close()
		err = tmpl.ExecuteTemplate(f, "_template."+ext, data)
		if err != nil {
			return err
		}
	}

	return nil
}

func main() {
	flag.Parse()
	err := Run(data)
	if err != nil {
		panic(err)
	}
}
