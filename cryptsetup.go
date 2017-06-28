package cryptsetup

// #cgo pkg-config: libcryptsetup
// #include <libcryptsetup.h>
// #include <stdlib.h>
import "C"
import (
	"unsafe"
	"runtime"
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

func (d Device) Format(key []bytes) error {
	params := &C.struct_crypt_params_luks1{
		hash: C.CString("sha256"), // most secure hash
		data_alignment: 0,	   // select the alignment
					   // according to what's best
					   // for the block device
		data_device: nil,	   // don't use a separate
					   // data device (keep the
					   // header and data
					   // together)
	}
	defer C.free(unsafe.Pointer(params.hash)) // free the C memory we allocated
	err := d.format(
		C.CRYPT_LUKS1,	// luks is what we want to use
		"aes",		// most secure encryption algorithm 
		"xts-plain64",	// most secure mode of operation
		"",		// generate the uuid
		nil,		// generate the volume key
		(unsafe.Pointer)(params), // the above parameters...
	)
	runtime.KeepAlive(params) // don't let the GC clean up this
				  // object while the C code is
				  // running
	if err != nil {
		return err
	}
	_, err = d.keyslotAddByVolumeKey(
		C.CRYPT_ANY_SLOT, // use the first available key slot
		nil,		  // use the saved volume key from
				  // formatting
		key,		  // the key we were passed
	)
	return err
}
