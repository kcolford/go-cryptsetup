package cryptsetup

// #cgo pkg-config: libcryptsetup
// #include <libcryptsetup.h>
// #include <stdlib.h>
import "C"
import (
	"unsafe"
)

// Device is a handle on the crypto device
type Device struct {
	cd *C.struct_crypt_device
}


// NewDevice creates a new device based on the name of a file/block
// device to encrypt. It is the caller's responsibility to ensure that
// `Close` gets called on the device (or a copy of the device).
func NewDevice(name string) (d Device, err error) {
	_name := C.CString(name)
	defer C.free(unsafe.Pointer(_name))
	ival := C.crypt_init(&d.cd, _name)
	err = newError(int(ival), "")
	return
}

// Close closes a Device and frees the associated context and
// resources.
func (d Device) Close() {
	C.crypt_free(d.cd)
}

// FormatLuks formats the Device as Luks encrypted block device.
func (d Device) FormatLuks(key []byte) error {
	err := d.formatLuks()
	if err != nil {
		return err
	}
	_, err = d.keyslotAddByVolumeKey(C.CRYPT_ANY_SLOT, nil, key)
	return err
}
