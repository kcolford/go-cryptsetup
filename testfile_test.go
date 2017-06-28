package cryptsetup

import (
	"testing"
	"io/ioutil"
	"os"
)

const luksSize = 1049600

type TestFile struct {
	name string
}

func (t TestFile) Name() string {
	return t.name
}

func (t TestFile) Close() {
	err := os.Remove(t.Name())
	if err != nil {
		panic(err)
	}
}

func NewTestFile() (t TestFile, err error) {
	f, err := ioutil.TempFile("", "cryptsetup-test")
	if err != nil {
		return
	}
	defer f.Close()
	err = f.Truncate(luksSize)
	if err != nil {
		return
	}
	t.name = f.Name()
	return
}

func TestMakeTestfile(t *testing.T) {
	f, err := NewTestFile()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	t.Log(f.Name())
}
