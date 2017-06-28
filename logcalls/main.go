// Generate crypt_* wrappers that also setup the log function for
// proper error reporting.

package main

import (
	"os"
	"text/template"
	"flag"
	"path"
)

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
