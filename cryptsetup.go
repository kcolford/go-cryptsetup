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

	// VolumeKeyBits is the number of in the master volume
	// key. This field is only relevant when formatting the
	// device.
	VolumeKeyBits uint

	// Cipher is the symmetric cypher used to encrypt the
	// device.
	//
	// Refer to /proc/crypto for valid values of this field.
	Cipher string

	// CipherMode is the mode of operation for the Cipher. See the
	// Wikipedia article
	// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
	// for more information on how to use this.
	//
	// Refer to /proc/crypto for valid values of this field.
	CipherMode string

	// Hash is the cryptographic hash function used for verifying
	// the decrypted Luks volume key. Without a hash of the volume
	// key it would be impossible to guarantee whether or not a
	// correct password was used to decrypt the drive (which could
	// lead to us accidentally corrupting said drive).
	//
	// Refer to /proc/crypto for valid values of this field.
	Hash string

	// Kdf is the Key Deriviation Function used to convert a given
	// password/keyfile into a key for decrypting
	Kdf string
}

const DefaultVolumeKeyBits = 256
const DefaultCipher = "aes"
const DefaultCipherMode = "xts-plain64"
const DefaultHash = "sha256"
const DefaultKdf = "pbkdf2"

// NewDevice creates a new device based on the name of a file/block
// device to encrypt. It is the caller's responsibility to ensure that
// `Close` gets called on the device (or a copy of the device).
func NewDevice(name string) (d *Device, err error) {
	d = &Device{
		VolumeKeyBits: DefaultVolumeKeyBits,
		Cipher: DefaultCipher,
		CipherMode: DefaultCipherMode,
		Hash: DefaultHash,
		Kdf: DefaultKdf,
	}
	
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
func (d *Device) Format(key []byte) error {
	params := &C.struct_crypt_params_luks1{
		hash: C.CString(d.Hash),
	}
	defer C.free(unsafe.Pointer(params.hash)) // free the C memory we allocated
	err := d.format(
		C.CRYPT_LUKS1,	// luks is what we want to use
		d.Cipher,
		d.CipherMode,
		"",		// generate the uuid
		nil,		// generate the volume key
		C.size_t(d.VolumeKeyBits / 8),
		unsafe.Pointer(params), // the above parameters...
	)
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

// Benchmark runs the library's internal benchmarking code on the
// underlying block device with the given parameters. It returns the
// number of MiB encrypted and decrypted per-second.
func (d *Device) Benchmark(iv_bits uint, buffer_size uint64) (float64, float64, error) {
	var enc, dec C.double
	err := d.benchmark(
		d.Cipher,
		d.CipherMode,
		C.size_t(d.VolumeKeyBits / 8),
		C.size_t(iv_bits / 8),
		C.size_t(buffer_size),
		&enc,
		&dec,
	)
	return float64(enc), float64(dec), err
}

// BenchmarkKdb runs the the library's internal benchmark code for the
// Key Deriviation Function. It returns the number hashes performed in
// one second on the password with the given salt.
//
// The number of hashes indicates the difficulty of bruteforcing the
// password; higher is more difficult to crack.
func (d *Device) BenchmarkKdf(pass, salt []byte) (uint64, error) {
	var iter C.uint64_t
	err := d.benchmarkKdf(d.Kdf, d.Hash, pass, salt, &iter)
	return uint64(iter), err
}

