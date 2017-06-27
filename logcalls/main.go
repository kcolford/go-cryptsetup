// Generate crypt_* wrappers that also setup the log function for
// proper error reporting.

package main

import (
	"text/template"
	"time"
	"os"
	"strings"
	"fmt"
)

type MethodParam struct {
	Type string
	Name string
	ForceArg string
}

type Method struct {
	Name string
	Params []MethodParam
	Return string
	Private bool
}

type Data struct {
	Now time.Time
	Ns string
	PackageName string
	BaseName string
	Methods []Method
}

var data = Data{
	Now: time.Now(),
	Ns: "gocrypt",
	PackageName: "cryptsetup",
	BaseName: "logcalls",
	Methods: []Method{
		{Name: "gocrypt_format_luks", Params: []MethodParam{
		}},
		{Name: "crypt_set_data_device", Params: []MethodParam{
			{Type: "const char *", Name: "device"},
		}},
		{Name: "crypt_get_rng_type", Params: []MethodParam{
		}, Return: "int"},
		{Name: "crypt_set_uuid", Params: []MethodParam{
			{Type: "const char *", Name: "uuid"},
		}},
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
		{Name: "crypt_activate_by_passphrase", Params: []MethodParam{
			{Type: "const char *", Name: "name"},
			{Type: "int", Name: "keyslot"},
			{Type: "void *", Name: "passphrase"},
			{Type: "size_t", Name: "passphrase_size",
				ForceArg: "len(passphrase)"},
			{Type: "uint32_t", Name: "flags"},
		}, Return: "int"},
	},
}

func (m Method) GoName() string {
	s := strings.Split(m.Name, "_")
	s = s[1:]
	for k := range s {
		s[k] = strings.Title(s[k])
	}
	s[0] = strings.ToLower(s[0])
	return strings.Join(s, "")
}

func (m Method) DeclParams() []MethodParam {
	out := make([]MethodParam, 0, len(m.Params))
	for _, p := range m.Params {
		if p.ForceArg == "" {
			out = append(out, p)
		}
	}
	return out
}

func (p MethodParam) Value() string {
	if p.ForceArg != "" {
		return p.ForceArg
	}
	return p.Name
}

type UnknownCType struct {
	Type string
}

func (err UnknownCType) Error() string {
	return fmt.Sprintf("unknown C type: %s", err.Type)
}

func (p MethodParam) GoType() (string, error) {
	switch p.Type {
	case "const char *":
		fallthrough 
	case "char *":
		return "string", nil
	case "const void *":
		fallthrough
	case "void *":
		return "[]byte", nil
	case "size_t":
		return "uint64", nil
	case "bool":
		fallthrough
	case "int":
		fallthrough
	case "uint32_t":
		fallthrough
	case "uint64_t":
		return strings.TrimSuffix(p.Type, "_t"), nil
	default:
		return "", UnknownCType{p.Type}
	}
}

func (d Data) FileName(ext string) string {
	return d.BaseName + "." + ext
}

func (d Data) HeaderGuard() string {
	return strings.Replace(strings.ToUpper(d.FileName("h")), ".", "_", -1)
}

func Run() error {
	tmpl, err := template.ParseGlob(data.BaseName + "/template.*")
	if err != nil {
		return err
	}

	for _, ext := range []string{"h", "c", "go"} {
		f, err := os.Create(data.FileName(ext))
		if err != nil {
			return err
		}
		defer f.Close()
		err = tmpl.ExecuteTemplate(f, "template." + ext, data)
		if err != nil {
			return err
		}
	}

	return nil
}

func main() {
	err := Run()
	if err != nil {
		panic(err)
	}
}
