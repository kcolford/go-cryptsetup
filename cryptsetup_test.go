package cryptsetup

import (
	"io/ioutil"
	"os"
	"testing"
	"time"
)

const luksSize = 1049600

func freeme(d Device, f *os.File) {
	d.Close()
	err := os.Remove(f.Name())
	if err != nil {
		panic(err)
	}
	err = f.Close()
	if err != nil {
		panic(err)
	}
}

func makeDeviceSize(luksSize int64) (d Device, f *os.File, err error) {
	f, err = ioutil.TempFile("", "go-cryptsetup_testfile")
	if err != nil {
		return
	}
	err = f.Truncate(luksSize)
	if err != nil {
		return
	}
	d, err = NewDevice(f.Name())
	if err != nil {
		return
	}

	// try shortening the key hashing time so that we're not
	// sitting here forever...
	d.SetIterationTime(10 * time.Millisecond)

	return
}

func makeDevice() (Device, *os.File, error) {
	return makeDeviceSize(luksSize)
}

var mypassword = []byte("my password")
var passwords = []string{
	"password",
	"lksdjfl sk",
	"asdfghjkl;'",
}

func TestDevice_Format(t *testing.T) {
	t.Parallel()

	for _, pass := range passwords {
		t.Run("key="+pass, func(t *testing.T) {
			t.Parallel()

			d, f, err := makeDevice()
			if err != nil {
				t.Fatal(err)
			}
			defer freeme(d, f)

			err = d.Format([]byte(pass), LuksParams{})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDevice(t *testing.T) {
	t.Parallel()

	d, f, err := makeDevice()
	if err != nil {
		t.Fatal(err)
	}
	defer freeme(d, f)

	err = d.Format(mypassword, LuksParams{})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("format", func(t *testing.T) {

		t.Run("addkeys", func(t *testing.T) {
			for _, pass := range passwords {
				t.Run(pass, func(t *testing.T) {
					err := d.AddKey(mypassword, []byte(pass))
					if err != nil {
						t.Fatal(err)
					}
				})
			}
		})

		t.Run("delkeys", func(t *testing.T) {
			for _, pass := range passwords {
				t.Run(pass, func(t *testing.T) {
					err := d.DelKey([]byte(pass))
					if err != nil {
						t.Fatal(err)
					}
				})
			}
		})

		t.Run("activate", func(t *testing.T) {
			if os.Geteuid() != 0 {
				t.Skip("only root can activate a device")
			}
			err := d.Activate("example_device", []byte("my password"))
			if err != nil {
				t.Fatal(err)
			}
		})

	})

	t.Run("load", func(t *testing.T) {

		t.Run("load-nil", func(t *testing.T) {
			d, err = NewDevice(f.Name())
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()

			err = d.Load(nil)
			if err != nil {
				t.Fatal(err)
			}
		})

		t.Run("load-luks", func(t *testing.T) {
			d, err = NewDevice(f.Name())
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()

			err = d.Load(LuksParams{})
			if err != nil {
				t.Fatal(err)
			}
		})

		t.Run("load-plain", func(t *testing.T) {
			d, err = NewDevice(f.Name())
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()

			err = d.Load(PlainParams{})
			if err != nil {
				return
			}
			t.Fail()
		})

	})

}

func TestNewDevice(t *testing.T) {
	t.Parallel()

	d, f, err := makeDevice()
	if err != nil {
		t.Fatal(err)
	}
	defer freeme(d, f)
}

func TestNewDevice_error(t *testing.T) {
	t.Parallel()

	d, err := NewDevice(os.DevNull)
	if err != nil {
		return
	}
	defer d.Close()
	t.Fail()
}

func TestDevice_Format_error(t *testing.T) {
	t.Parallel()

	d, f, err := makeDeviceSize(luksSize / 2)
	if err != nil {
		t.Fatal(err)
	}
	defer freeme(d, f)

	err = d.Format([]byte("password"), LuksParams{})
	if err != nil {
		return
	}
	t.Fail()
}
