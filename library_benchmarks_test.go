package cryptsetup

import (
	"testing"
)

func BenchmarkLibrary(b *testing.B) {
	f, err := NewTestFile()
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()

	d, err := NewDevice(f.Name())
	if err != nil {
		b.Fatal(err)
	}
	defer d.Close()
}
