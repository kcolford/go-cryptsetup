package cryptsetup

// #cgo pkg-config: libcryptsetup
// #include <libcryptsetup.h>
// #include <stdlib.h>
import "C"
import (
	"unsafe"
)

const (
	DefaultCipher = "aes"
	DefaultMode   = "xts-plain64"
	DefaultHash   = "sha256"
)

type CryptParameter interface {
	CMode() (string, Params, unsafe.Pointer, func())
}

type Params struct {
	Cipher        string
	Mode          string
	VolumeKeyBits uintptr
}

func (pp *Params) def() {
	if pp.Cipher == "" {
		pp.Cipher = DefaultCipher
	}
	if pp.Mode == "" {
		pp.Mode = DefaultMode
	}
	if pp.VolumeKeyBits == 0 {
		pp.VolumeKeyBits = 256
	}
}

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
		hash:   cString(p.Hash),
		offset: C.uint64_t(p.Offset),
		skip:   C.uint64_t(p.Skip),
		size:   C.uint64_t(p.Size),
	}
	out = C.malloc(C.sizeof_struct_crypt_params_plain)
	*(*C.struct_crypt_params_plain)(out) = s
	free = func() {
		cBytesFree(out)
		cStringFree(s.hash)
	}
	return
}

type LuksParams struct {
	Params
	Hash          string // hash used in LUKS header
	DataAlignment uint64 // data alignment (in sectors)
	DataDevice    string // detached encrypted data device or ""
}

func (p LuksParams) CMode() (t string, pp Params, out unsafe.Pointer, free func()) {
	p.def()
	if p.Hash == "" {
		p.Hash = DefaultHash
	}

	t = C.CRYPT_LUKS1
	pp = p.Params
	s := C.struct_crypt_params_luks1{
		hash:           cString(p.Hash),
		data_alignment: C.size_t(p.DataAlignment),
		data_device:    cString(p.DataDevice),
	}
	out = C.malloc(C.sizeof_struct_crypt_params_luks1)
	*(*C.struct_crypt_params_luks1)(out) = s
	free = func() {
		cBytesFree(out)
		cStringFree(s.hash)
		cStringFree(s.data_device)
	}
	return
}
