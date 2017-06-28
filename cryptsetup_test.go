package cryptsetup

import (
	"testing"
)

func TestBasic(t *testing.T) {
	f, err := NewTestFile()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	d, err := NewDevice(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	err = d.FormatLuks([]byte("password"))
	if err != nil {
		t.Fatal(err)
	}
}
