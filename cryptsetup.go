package cryptsetup

// #cgo pkg-config: libcryptsetup
// #include <libcryptsetup.h>
import "C"
import (
	"time"
)

// Device is a handle on the crypto device. It corresponds to a
// `struct crypt_device*` in libcryptsetup
type Device struct {
	cd *C.struct_crypt_device
}

// synchronize the first time secure memory is allocated, otherwise
// libgcrypt's secure memory pool may be inititialized multiple times
var firstInitStatus = make(chan int, 1)
func init() {
	firstInitStatus <- 0
}

// NewDevice creates a new device based on the name of a file/block
// device to encrypt. It is the caller's responsibility to ensure that
// `Close` gets called on the device (or a copy of the device).
func NewDevice(name string) (d *Device, err error) {
	d = new(Device)
	err = d.init(name)
	return
}

// Close closes a Device and frees the associated context and
// resources.
func (d *Device) Close() {
	C.crypt_free(d.cd)
}

// Load loads the device header into the device context.
func (d *Device) Load(p CryptParameter) error {
	if p == nil {
		return d.load(nil, nil)
	}
	t, _, params, free := p.CMode()
	defer free()
	return d.load(&t, params)
}

// Format formats the block device
func (d *Device) Format(key []byte, p CryptParameter) error {
	if _, ok := <-firstInitStatus; ok {
		defer close(firstInitStatus)
	}

	t, pp, params, free := p.CMode()
	defer free()
	err := d.format(
		t,
		pp.Cipher,
		pp.Mode,
		nil,		  // generate the uuid
		nil,		  // generate the volume key
		pp.VolumeKeySize, // 256bit volume key
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

// Benchmark runs the library's internal benchmarking code on the
// underlying block device with the given parameters. It returns the
// number of MiB encrypted and decrypted per-second.
func (d *Device) Benchmark(iv_size uint64, buffer_size uint64, pp Params) (enc float64, dec float64, err error) {
	pp.def()
	var cenc, cdec C.double
	err = d.benchmark(
		pp.Cipher,
		pp.Mode,
		pp.VolumeKeySize,
		iv_size,
		buffer_size,
		&cenc,
		&cdec,
	)
	enc = float64(cenc)
	dec = float64(cdec)
	return
}

// BenchmarkKdf runs the the library's internal benchmark code for the
// Key Deriviation Function. It returns the number hashes performed in
// one second on the password with the given salt.
//
// The number of hashes indicates the difficulty of bruteforcing the
// password; higher is more difficult to crack.
func (d *Device) BenchmarkKdf(hash string, pass, salt []byte) (iter uint64, err error) {
	if hash == "" {
		hash = DefaultHash
	}
	err = d.benchmarkKdf("pbkdf2", hash, pass, salt, (*C.uint64_t)(&iter))
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
		&name,
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

// Name returns the name of the underlying device. This is the same as
// the argument passed to NewDevice.
func (d *Device) Name() string {
	return C.GoString(C.crypt_get_device_name(d.cd))
}

// Uuid returns the UUID of the device.
func (d *Device) Uuid() string {
	return C.GoString(C.crypt_get_uuid(d.cd))
}

// SetUuid sets the uuid of the device
func (d *Device) SetUuid(uuid string) error {
	return d.setUuid(uuid)
}

// Params returns a Params object with the cryptographic parameters
// used by the device.
func (d *Device) Params() (pp Params) {
	pp.Cipher = C.GoString(C.crypt_get_cipher(d.cd))
	pp.Mode = C.GoString(C.crypt_get_cipher_mode(d.cd))
	pp.VolumeKeySize = uint64(C.crypt_get_volume_key_size(d.cd))
	return
}

// SetIterationTime sets how log it should take to construct a key
// from a password. The default is about 1 second.
func (d *Device) SetIterationTime(t time.Duration) {
	C.crypt_set_iteration_time(d.cd, C.uint64_t(t.Seconds() * 1000))
}

// SetDataDevice specifies a device to use in detached header mode.
func (d *Device) SetDataDevice(name string) error {
	return d.setDataDevice(name)
}

// AddKey adds a new password, newpass, to the block device, first
// unlocking it with pass.
func (d *Device) AddKey(pass []byte, newpass []byte) error {
	if _, ok := <-firstInitStatus; ok {
		defer close(firstInitStatus)
	}

	_, err := d.keyslotAddByPassphrase(C.CRYPT_ANY_SLOT, pass, newpass)
	return err
}

// DelKey removes the password specified by pass from the device,
// effectively making it impossible to decrypt the device with that
// password any more. Note that this is not guaranteed to work on SSDs
// and flash memory because the wear leveling technology used in those
// devices makes it impossible to ensure complete erasure of the data
// in a specific sector.
func (d *Device) DelKey(pass []byte) (err error) {
	i, err := d.activateByPassphrase(nil, C.CRYPT_ANY_SLOT, pass, 0)
	if err != nil {
		return
	}
	err = d.keyslotDestroy(i)
	return
}
