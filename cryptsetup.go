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
func NewDevice(name string) (d *Device, err error) {
	d = &Device{}
	_name := (*C.char)(nil)
	if name != "" {
		_name = C.CString(name)
		defer C.free(unsafe.Pointer(_name))
	}
	ival := C.crypt_init(&d.cd, _name)
	err = newError(int(ival), nil)
	return
}

// Close closes a Device and frees the associated context and
// resources.
func (d *Device) Close() {
	C.crypt_free(d.cd)
}

// Format formats the block device
func (d *Device) Format(key []byte, p CryptParameter) error {
	t, pp, params, free := p.CMode()
	defer free()
	err := d.format(
		t,
		pp.Cipher,
		pp.Mode,
		"",		      // generate the uuid
		nil,		      // generate the volume key
		pp.VolumeKeyBits / 8, // 256bit volume key
		params,
	)
	if err != nil {
		return err
	}
	_, err = d.keyslotAddByPassphrase(
		C.CRYPT_ANY_SLOT, // use the first available key slot
		nil,		  // use the saved volume key from
				  // formatting
		key,		  // the key we were passed
	)
	return err
}

func (d *Device) Load(p CryptParameter) error {
	if p == nil {
		return d.load("", nil)
	}
	t, _, params, free := p.CMode()
	defer free()
	return d.load(t, params)
}
		

// Benchmark runs the library's internal benchmarking code on the
// underlying block device with the given parameters. It returns the
// number of MiB encrypted and decrypted per-second.
func (d *Device) Benchmark(iv_bits uintptr, buffer_size uintptr, pp Params) (enc float64, dec float64, err error) {
	pp.def()
	var cenc, cdec C.double
	err = d.benchmark(
		pp.Cipher,
		pp.Mode,
		pp.VolumeKeyBits / 8,
		iv_bits / 8,
		buffer_size,
		&cenc,
		&cdec,
	)
	enc = float64(cenc)
	dec = float64(cdec)
	return
}

// BenchmarkKdb runs the the library's internal benchmark code for the
// Key Deriviation Function. It returns the number hashes performed in
// one second on the password with the given salt.
//
// The number of hashes indicates the difficulty of bruteforcing the
// password; higher is more difficult to crack.
func (d *Device) BenchmarkKdf(hash string, pass, salt []byte) (iter uint64, err error) {
	if hash == "" {
		hash = DefaultHash
	}
	var citer C.uint64_t
	err = d.benchmarkKdf("pbkdf2", hash, pass, salt, &citer)
	iter = uint64(iter)
	return
}

// Dir returns the directory were the decrypted devices are placed.
func Dir() string {
	return C.GoString(C.crypt_get_dir())
}

// Activate sets up the encrypted volume as name under the directory
// specified by Dir().
func (d *Device) Activate(name string, pass []byte) error {
	_, err := d.activateByPassphrase(
		name,
		C.CRYPT_ANY_SLOT,
		pass,
		0,
	)
	return err
}

// Deactivate removes the active device-mapper mapping from the
// kernel. This also removes sensitive data from memory.
func (d *Device) Deactivate(name string) error {
	return d.deactivate(name)
}

// name returns the name of the underlying device. This is the same as
// the argument passed to NewDevice.
func (d *Device) Name() string {
	return C.GoString(C.crypt_get_device_name(d.cd))
}

// Uuid returns the UUID of the device. It may return the empty string
// if the device's UUID has not been set.
func (d *Device) Uuid() string {
	out := C.crypt_get_uuid(d.cd)
	if out != nil {
		return C.GoString(out)
	}
	return ""
}

func (d *Device) SetUuid(uuid string) error {
	return d.setUuid(uuid)
}
