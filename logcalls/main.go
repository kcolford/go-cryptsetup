// Generate crypt_* wrappers that also setup the log function for
// proper error reporting.

package main

import (
	"os"
	"text/template"
	"flag"
	"path"
	"time"
	"strings"
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

type Data struct {
	// the time at which the sources are being generated, to be
	// added in a comment
	Now time.Time

	// the namespace in which to place the generated C functions,
	// this will be prepended along with an underscore to the the
	// method names
	Ns string

	// the name of the Go package
	PackageName string

	// the basename of the generated files
	BaseName string

	// the methods to be rebound
	Methods []Method
}

var data = Data{
	Now:         time.Now(),
	Ns:          "gocrypt",
	PackageName: "cryptsetup",
	BaseName:    "logcalls",
	Methods: []Method{
		// formatting
		{Name: "gocrypt_format_luks", Params: []MethodParam{}},

		// misc
		{Name: "crypt_set_data_device", Params: []MethodParam{
			{Type: "const char *", Name: "device"},
		}},
		{Name: "crypt_get_rng_type", Params: []MethodParam{}, Return: "int"},
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
		{Name: "crypt_keyslot_change_by_passphrase", Params: []MethodParam{
			{Type: "int", Name: "keyslot_old"},
			{Type: "int", Name: "keyslot_new"},
			{Type: "void *", Name: "passphrase"},
			{Type: "size_t", Name: "passphrase_size",
				ForceArg: "len(passphrase)"},
			{Type: "void *", Name: "new_passphrase"},
			{Type: "size_t", Name: "new_passphrase_size",
				ForceArg: "len(new_passphrase)"},
		}, Return: "int"},
		{Name: "crypt_keyslot_add_by_keyfile_offset", Params: []MethodParam{
			{Type: "int", Name: "keyslot"},
			{Type: "const char *", Name: "keyfile"},
			{Type: "size_t", Name: "keyfile_size"},
			{Type: "size_t", Name: "keyfile_offset"},
			{Type: "const char *", Name: "new_keyfile"},
			{Type: "size_t", Name: "new_keyfile_size"},
			{Type: "size_t", Name: "new_keyfile_offset"},
		}},
		{Name: "crypt_keyslot_add_by_volume_key", Params: []MethodParam{
			{Type: "int", Name: "keyslot"},
			{Type: "void *", Name: "volume_key"},
			{Type: "size_t", Name: "volume_key_size",
				ForceArg: "len(volume_key)"},
			{Type: "void *", Name: "passphrase"},
			{Type: "size_t", Name: "passphrase_size",
				ForceArg: "len(passphrase)"},
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
		{Name: "crypt_activate_by_keyfile_offset", Params: []MethodParam{
			{Type: "const char *", Name: "name"},
			{Type: "int", Name: "keyslot"},
			{Type: "const char *", Name: "keyfile"},
			{Type: "size_t", Name: "keyfile_size"},
			{Type: "size_t", Name: "keyfile_offset"},
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


func Templates(dir string) (*template.Template, error) {
	return template.ParseGlob(path.Join(dir, "template.*"))
}

func Run(dir string) error {
	tmpl, err := Templates(dir)
	if err != nil {
		return err
	}

	for _, ext := range []string{"h", "c", "go"} {
		f, err := os.Create(data.FileName(ext))
		if err != nil {
			return err
		}
		defer f.Close()
		err = tmpl.ExecuteTemplate(f, "template."+ext, data)
		if err != nil {
			return err
		}
	}

	return nil
}

func main() {
	mydirectory := flag.String("d", "./templates", "the directory where templates can be found")
	flag.Parse()

	err := Run(*mydirectory)
	if err != nil {
		panic(err)
	}
}
