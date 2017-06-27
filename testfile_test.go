package cryptsetup

import (
	"io/ioutil"
	"os"
	"testing"
)

const luksSize = 1049600

func NewTestFile(t *testing.T) string {
	f, err := ioutil.TempFile("", "cryptsetup-test")
	if err != nil {
		t.Fatal("new testfile", err)
	}
	defer f.Close()
	err = f.Truncate(luksSize)
	if err != nil {
		t.Fatal("new testfile", err)
	}
	return f.Name()
}

func CloseTestFile(t *testing.T, f string) {
	err := os.Remove(f)
	if err != nil {
		t.Error("close testfile", err)
	}
}

func TestMakeTestfile(t *testing.T) {
	t.Log("making testfile")
	f := NewTestFile(t)
	t.Log(f)
	defer CloseTestFile(t, f)
}
