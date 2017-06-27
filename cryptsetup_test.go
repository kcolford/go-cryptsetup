package cryptsetup

import (
	"testing"
)

func TestBasic(t *testing.T) {
	f := NewTestFile(t)
	defer CloseTestFile(t, f)
	d, err := NewDevice(f)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	err = d.FormatLuks([]byte("password"))
	if err != nil {
		t.Fatal(err)
	}
}
