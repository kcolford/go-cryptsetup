package cryptsetup

// #cgo pkg-config: libcryptsetup
// #include <libcryptsetup.h>
// #include <stdlib.h>
import "C"
import (
	"unsafe"
)

// Default cipher settings designed to maximize the security of one's
// data.
const (
	DefaultCipher = "aes"
	DefaultMode   = "xts-plain64"
	DefaultHash   = "sha256"
)

type CryptParameter interface {
	CMode() (string, Params, unsafe.Pointer, func())
}

// Params consists of common parameters used by the various
// cryptographic backends.
type Params struct {
	Cipher        string
	Mode          string
	VolumeKeySize uint64
}

func (pp *Params) def() {
	if pp.Cipher == "" {
		pp.Cipher = DefaultCipher
	}
	if pp.Mode == "" {
		pp.Mode = DefaultMode
	}
	if pp.VolumeKeySize == 0 {
		pp.VolumeKeySize = 256 / 8
	}
}

// PlainParams is the set of parameters used for performing plain
// headerless encryption of a block device. Using this, the device is
// indistinguishable from truly random data.
//
// While this can be useful for deniable encryption, it is not perfect
// as an adversary who may suspect such deniable encryption is in use
// whenever they see "truly random data" can use various interrogation
// techniques to force the password out of a user. Cases when it may
// be useful include: when ordered by a judge to provide a password
// for a drive, one can claim that there is no password and the drive
// is full of random data, in this case it is impossible to "prove"
// (as in beyond any reasonable doubt) that a user is in fact keeping
// a password from authorities.
//
// I am not a lawyer and the laws in your jurisdiction may be
// different. Do not take any of this as professional legal advice.
type PlainParams struct {
	Params
	Hash   string // password hash function
	Offset uint64 // offset (in sectors)
	Skip   uint64 // IV offset / initialization sector
	Size   uint64 // size of mapped device or 0
}

func (p PlainParams) CMode() (t string, pp Params, out unsafe.Pointer, free func()) {
	p.def()
	if p.Hash == "" {
		p.Hash = DefaultHash
	}

	t = C.CRYPT_PLAIN
	pp = p.Params
	s := C.struct_crypt_params_plain{
		hash:   C.CString(p.Hash),
		offset: C.uint64_t(p.Offset),
		skip:   C.uint64_t(p.Skip),
		size:   C.uint64_t(p.Size),
	}
	out = C.malloc(C.sizeof_struct_crypt_params_plain)
	*(*C.struct_crypt_params_plain)(out) = s
	free = func() {
		C.free(out)
		C.free(unsafe.Pointer(s.hash))
	}
	return
}

// LuksParams is the set of parameters used for defining operations on
// LUKS based encrypted devices.
type LuksParams struct {
	Params
	Hash          string  // hash used in LUKS header
	DataAlignment uint64  // data alignment (in sectors)
	DataDevice    *string // detached encrypted data device or ""
}

func (p LuksParams) CMode() (t string, pp Params, out unsafe.Pointer, free func()) {
	p.def()
	if p.Hash == "" {
		p.Hash = DefaultHash
	}

	t = C.CRYPT_LUKS1
	pp = p.Params
	s := C.struct_crypt_params_luks1{
		hash:           C.CString(p.Hash),
		data_alignment: C.size_t(p.DataAlignment),
		data_device:    nil,
	}
	if p.DataDevice != nil {
		s.data_device = C.CString(*p.DataDevice)
	}
	out = C.malloc(C.sizeof_struct_crypt_params_luks1)
	*(*C.struct_crypt_params_luks1)(out) = s
	free = func() {
		C.free(out)
		C.free(unsafe.Pointer(s.hash))
		if s.data_device != nil {
			C.free(unsafe.Pointer(s.data_device))
		}

	}
	return
}
