package cryptsetup

import (
	"os"
	"testing"
)

const luksSize = 1049600
const tempFile = "/tmp/go-cryptsetup_cryptsetup_test_imagefile"

func makeDeviceSize(luksSize int64) (d *Device, err error) {
	f, err := os.Create(tempFile)
	if err != nil {
		return
	}
	defer f.Close()
	err = f.Truncate(luksSize)
	if err != nil {
		return
	}
	return NewDevice(f.Name())
}

func makeDevice() (*Device, error) {
	return makeDeviceSize(luksSize)
}

var passwords = []string{
	"password",
	"lksdjfl sk",
	"asdfghjkl;'",
}

func TestDevice_Format(t *testing.T) {
	for _, pass := range passwords {
		t.Run("key="+pass, func(t *testing.T) {
			d, err := makeDevice()
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()

			err = d.Format([]byte(pass))
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNewDevice(t *testing.T) {
	d, err := makeDevice()
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
}

func TestNewDevice_error(t *testing.T) {
	d, err := NewDevice(os.DevNull)
	if err != nil {
		t.Log(err)
		return
	}
	defer d.Close()
	t.FailNow()
}

func TestDevice_Format_error(t *testing.T) {
	d, err := makeDeviceSize(luksSize / 2)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	err = d.Format([]byte("password"))
	if err == nil {
		t.FailNow()
	}
	t.Log(err)
}
