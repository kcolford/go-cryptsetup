
package cryptsetup

// #cgo pkg-config: libcryptsetup
// #include <libcryptsetup.h>
// #include <stdlib.h>
// #include "logcalls.h"
// #include "log.h"
import "C"
import (
	"unsafe"
)


func (d Device) format(format string, cipher string, cipher_mode string, uuid string, volume_key []byte, volume_key_size uintptr, params unsafe.Pointer) (err error) {
	arglist := (*C.struct_gocrypt_logstack)(nil)
	
	
	_format := cString(format)
	defer cStringFree(_format)
	
	
	
	_cipher := cString(cipher)
	defer cStringFree(_cipher)
	
	
	
	_cipher_mode := cString(cipher_mode)
	defer cStringFree(_cipher_mode)
	
	
	
	_uuid := cString(uuid)
	defer cStringFree(_uuid)
	
	
	
	_volume_key := cBytes(volume_key)
	defer cBytesFree(_volume_key)
	
	
	
	_volume_key_size := (C.size_t)(volume_key_size)
	
	
	
	_params := (unsafe.Pointer)(params)
	
	
	
	ival := C.gocrypt_crypt_format(
		&arglist,
		d.cd,
		
		_format,
		
		_cipher,
		
		_cipher_mode,
		
		_uuid,
		
		_volume_key,
		
		_volume_key_size,
		
		_params,
		
	)
	
	err = newError(int(ival), logMessages(arglist))
	
	return
}

func (d Device) load(requested_type string, params unsafe.Pointer) (err error) {
	arglist := (*C.struct_gocrypt_logstack)(nil)
	
	
	_requested_type := cString(requested_type)
	defer cStringFree(_requested_type)
	
	
	
	_params := (unsafe.Pointer)(params)
	
	
	
	ival := C.gocrypt_crypt_load(
		&arglist,
		d.cd,
		
		_requested_type,
		
		_params,
		
	)
	
	err = newError(int(ival), logMessages(arglist))
	
	return
}

func (d Device) getRngType() (out int, err error) {
	arglist := (*C.struct_gocrypt_logstack)(nil)
	
	
	ival := C.gocrypt_crypt_get_rng_type(
		&arglist,
		d.cd,
		
	)
	
	err = newError(int(ival), logMessages(arglist))
	out = (int)(ival)
	return
}

func (d Device) setUuid(uuid string) (err error) {
	arglist := (*C.struct_gocrypt_logstack)(nil)
	
	
	_uuid := cString(uuid)
	defer cStringFree(_uuid)
	
	
	
	ival := C.gocrypt_crypt_set_uuid(
		&arglist,
		d.cd,
		
		_uuid,
		
	)
	
	err = newError(int(ival), logMessages(arglist))
	
	return
}

func (d Device) keyslotAddByPassphrase(keyslot int, passphrase []byte, new_passphrase []byte) (out int, err error) {
	arglist := (*C.struct_gocrypt_logstack)(nil)
	
	
	_keyslot := (C.int)(keyslot)
	
	
	
	_passphrase := cBytes(passphrase)
	defer cBytesFree(_passphrase)
	
	
	
	_passphrase_size := (C.size_t)(len(passphrase))
	
	
	
	_new_passphrase := cBytes(new_passphrase)
	defer cBytesFree(_new_passphrase)
	
	
	
	_new_passphrase_size := (C.size_t)(len(new_passphrase))
	
	
	
	ival := C.gocrypt_crypt_keyslot_add_by_passphrase(
		&arglist,
		d.cd,
		
		_keyslot,
		
		_passphrase,
		
		_passphrase_size,
		
		_new_passphrase,
		
		_new_passphrase_size,
		
	)
	
	err = newError(int(ival), logMessages(arglist))
	out = (int)(ival)
	return
}

func (d Device) keyslotDestroy(keyslot int) (err error) {
	arglist := (*C.struct_gocrypt_logstack)(nil)
	
	
	_keyslot := (C.int)(keyslot)
	
	
	
	ival := C.gocrypt_crypt_keyslot_destroy(
		&arglist,
		d.cd,
		
		_keyslot,
		
	)
	
	err = newError(int(ival), logMessages(arglist))
	
	return
}

func (d Device) activateByPassphrase(name string, keyslot int, passphrase []byte, flags C.uint32_t) (out int, err error) {
	arglist := (*C.struct_gocrypt_logstack)(nil)
	
	
	_name := cString(name)
	defer cStringFree(_name)
	
	
	
	_keyslot := (C.int)(keyslot)
	
	
	
	_passphrase := cBytes(passphrase)
	defer cBytesFree(_passphrase)
	
	
	
	_passphrase_size := (C.size_t)(len(passphrase))
	
	
	
	_flags := (C.uint32_t)(flags)
	
	
	
	ival := C.gocrypt_crypt_activate_by_passphrase(
		&arglist,
		d.cd,
		
		_name,
		
		_keyslot,
		
		_passphrase,
		
		_passphrase_size,
		
		_flags,
		
	)
	
	err = newError(int(ival), logMessages(arglist))
	out = (int)(ival)
	return
}

func (d Device) deactivate(name string) (err error) {
	arglist := (*C.struct_gocrypt_logstack)(nil)
	
	
	_name := cString(name)
	defer cStringFree(_name)
	
	
	
	ival := C.gocrypt_crypt_deactivate(
		&arglist,
		d.cd,
		
		_name,
		
	)
	
	err = newError(int(ival), logMessages(arglist))
	
	return
}

func (d Device) benchmark(cipher string, cipher_mode string, volume_key_size uintptr, iv_size uintptr, buffer_size uintptr, encryption_mbs *C.double, decryption_mbs *C.double) (err error) {
	arglist := (*C.struct_gocrypt_logstack)(nil)
	
	
	_cipher := cString(cipher)
	defer cStringFree(_cipher)
	
	
	
	_cipher_mode := cString(cipher_mode)
	defer cStringFree(_cipher_mode)
	
	
	
	_volume_key_size := (C.size_t)(volume_key_size)
	
	
	
	_iv_size := (C.size_t)(iv_size)
	
	
	
	_buffer_size := (C.size_t)(buffer_size)
	
	
	
	_encryption_mbs := (*C.double)(encryption_mbs)
	
	
	
	_decryption_mbs := (*C.double)(decryption_mbs)
	
	
	
	ival := C.gocrypt_crypt_benchmark(
		&arglist,
		d.cd,
		
		_cipher,
		
		_cipher_mode,
		
		_volume_key_size,
		
		_iv_size,
		
		_buffer_size,
		
		_encryption_mbs,
		
		_decryption_mbs,
		
	)
	
	err = newError(int(ival), logMessages(arglist))
	
	return
}

func (d Device) benchmarkKdf(kdf string, hash string, password []byte, salt []byte, iterations_sec *C.uint64_t) (err error) {
	arglist := (*C.struct_gocrypt_logstack)(nil)
	
	
	_kdf := cString(kdf)
	defer cStringFree(_kdf)
	
	
	
	_hash := cString(hash)
	defer cStringFree(_hash)
	
	
	
	_password := cBytes(password)
	defer cBytesFree(_password)
	
	
	
	_password_size := (C.size_t)(len(password))
	
	
	
	_salt := cBytes(salt)
	defer cBytesFree(_salt)
	
	
	
	_salt_size := (C.size_t)(len(salt))
	
	
	
	_iterations_sec := (*C.uint64_t)(iterations_sec)
	
	
	
	ival := C.gocrypt_crypt_benchmark_kdf(
		&arglist,
		d.cd,
		
		_kdf,
		
		_hash,
		
		_password,
		
		_password_size,
		
		_salt,
		
		_salt_size,
		
		_iterations_sec,
		
	)
	
	err = newError(int(ival), logMessages(arglist))
	
	return
}

