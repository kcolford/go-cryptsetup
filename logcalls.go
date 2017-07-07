
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


func (d *Device) init(name string) (err error) {
	arglist := (*C.struct_gocrypt_logstack)(nil)
	
	
	_name := C.CString(name)
	defer C.free(unsafe.Pointer(_name))
	
	
	
	ival := C.gocrypt_crypt_init(
		&arglist,
		&d.cd,
		
		_name,
		
	)
	
	err = newError(int(ival), logMessages(arglist))
	
	return
}

func (d *Device) format(format string, cipher string, cipher_mode string, uuid *string, volume_key []byte, volume_key_size uint64, params unsafe.Pointer) (err error) {
	arglist := (*C.struct_gocrypt_logstack)(nil)
	
	
	_format := C.CString(format)
	defer C.free(unsafe.Pointer(_format))
	
	
	
	_cipher := C.CString(cipher)
	defer C.free(unsafe.Pointer(_cipher))
	
	
	
	_cipher_mode := C.CString(cipher_mode)
	defer C.free(unsafe.Pointer(_cipher_mode))
	
	
	
	var _uuid *C.char
	if uuid != nil {
		_uuid = C.CString(*uuid)
		defer C.free(unsafe.Pointer(_uuid))
	}
	
	
	
	_volume_key := unsafe.Pointer(nil)
	if volume_key != nil {
		_volume_key = C.CBytes(volume_key)
		defer C.free(_volume_key)
	} else {
		
		// this value can be nil
		
	}
	
	
	
	
	// not a pointer
	
	_volume_key_size := (C.size_t)(volume_key_size)
	
	
	
	
	// not a pointer
	
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

func (d *Device) load(requested_type *string, params unsafe.Pointer) (err error) {
	arglist := (*C.struct_gocrypt_logstack)(nil)
	
	
	var _requested_type *C.char
	if requested_type != nil {
		_requested_type = C.CString(*requested_type)
		defer C.free(unsafe.Pointer(_requested_type))
	}
	
	
	
	
	// not a pointer
	
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

func (d *Device) getRngType() (out int, err error) {
	arglist := (*C.struct_gocrypt_logstack)(nil)
	
	
	ival := C.gocrypt_crypt_get_rng_type(
		&arglist,
		d.cd,
		
	)
	
	err = newError(int(ival), logMessages(arglist))
	out = (int)(ival)
	return
}

func (d *Device) setUuid(uuid string) (err error) {
	arglist := (*C.struct_gocrypt_logstack)(nil)
	
	
	_uuid := C.CString(uuid)
	defer C.free(unsafe.Pointer(_uuid))
	
	
	
	ival := C.gocrypt_crypt_set_uuid(
		&arglist,
		d.cd,
		
		_uuid,
		
	)
	
	err = newError(int(ival), logMessages(arglist))
	
	return
}

func (d *Device) setDataDevice(name string) (err error) {
	arglist := (*C.struct_gocrypt_logstack)(nil)
	
	
	_name := C.CString(name)
	defer C.free(unsafe.Pointer(_name))
	
	
	
	ival := C.gocrypt_crypt_set_data_device(
		&arglist,
		d.cd,
		
		_name,
		
	)
	
	err = newError(int(ival), logMessages(arglist))
	
	return
}

func (d *Device) keyslotAddByPassphrase(keyslot int, passphrase []byte, new_passphrase []byte) (out int, err error) {
	arglist := (*C.struct_gocrypt_logstack)(nil)
	
	
	
	// not a pointer
	
	_keyslot := (C.int)(keyslot)
	
	
	
	_passphrase := unsafe.Pointer(nil)
	if passphrase != nil {
		_passphrase = C.CBytes(passphrase)
		defer C.free(_passphrase)
	} else {
		
		// this value can be nil
		
	}
	
	
	
	
	// not a pointer
	
	_passphrase_size := (C.size_t)(len(passphrase))
	
	
	
	_new_passphrase := unsafe.Pointer(nil)
	if new_passphrase != nil {
		_new_passphrase = C.CBytes(new_passphrase)
		defer C.free(_new_passphrase)
	} else {
		
		panic("nil unexpected")
		
	}
	
	
	
	
	// not a pointer
	
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

func (d *Device) keyslotDestroy(keyslot int) (err error) {
	arglist := (*C.struct_gocrypt_logstack)(nil)
	
	
	
	// not a pointer
	
	_keyslot := (C.int)(keyslot)
	
	
	
	ival := C.gocrypt_crypt_keyslot_destroy(
		&arglist,
		d.cd,
		
		_keyslot,
		
	)
	
	err = newError(int(ival), logMessages(arglist))
	
	return
}

func (d *Device) activateByPassphrase(name *string, keyslot int, passphrase []byte, flags uint32) (out int, err error) {
	arglist := (*C.struct_gocrypt_logstack)(nil)
	
	
	var _name *C.char
	if name != nil {
		_name = C.CString(*name)
		defer C.free(unsafe.Pointer(_name))
	}
	
	
	
	
	// not a pointer
	
	_keyslot := (C.int)(keyslot)
	
	
	
	_passphrase := unsafe.Pointer(nil)
	if passphrase != nil {
		_passphrase = C.CBytes(passphrase)
		defer C.free(_passphrase)
	} else {
		
		panic("nil unexpected")
		
	}
	
	
	
	
	// not a pointer
	
	_passphrase_size := (C.size_t)(len(passphrase))
	
	
	
	
	// not a pointer
	
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

func (d *Device) getActiveDevice(name string, cad *C.struct_crypt_active_device) (err error) {
	arglist := (*C.struct_gocrypt_logstack)(nil)
	
	
	_name := C.CString(name)
	defer C.free(unsafe.Pointer(_name))
	
	
	
	
	
	if cad == nil {
		panic("nil unexpected")
	}
	
	
	_cad := (*C.struct_crypt_active_device)(cad)
	
	
	
	ival := C.gocrypt_crypt_get_active_device(
		&arglist,
		d.cd,
		
		_name,
		
		_cad,
		
	)
	
	err = newError(int(ival), logMessages(arglist))
	
	return
}

func (d *Device) deactivate(name string) (err error) {
	arglist := (*C.struct_gocrypt_logstack)(nil)
	
	
	_name := C.CString(name)
	defer C.free(unsafe.Pointer(_name))
	
	
	
	ival := C.gocrypt_crypt_deactivate(
		&arglist,
		d.cd,
		
		_name,
		
	)
	
	err = newError(int(ival), logMessages(arglist))
	
	return
}

func (d *Device) benchmark(cipher string, cipher_mode string, volume_key_size uint64, iv_size uint64, buffer_size uint64, encryption_mbs *C.double, decryption_mbs *C.double) (err error) {
	arglist := (*C.struct_gocrypt_logstack)(nil)
	
	
	_cipher := C.CString(cipher)
	defer C.free(unsafe.Pointer(_cipher))
	
	
	
	_cipher_mode := C.CString(cipher_mode)
	defer C.free(unsafe.Pointer(_cipher_mode))
	
	
	
	
	// not a pointer
	
	_volume_key_size := (C.size_t)(volume_key_size)
	
	
	
	
	// not a pointer
	
	_iv_size := (C.size_t)(iv_size)
	
	
	
	
	// not a pointer
	
	_buffer_size := (C.size_t)(buffer_size)
	
	
	
	
	
	if encryption_mbs == nil {
		panic("nil unexpected")
	}
	
	
	_encryption_mbs := (*C.double)(encryption_mbs)
	
	
	
	
	
	if decryption_mbs == nil {
		panic("nil unexpected")
	}
	
	
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

func (d *Device) benchmarkKdf(kdf string, hash string, password []byte, salt []byte, iterations_sec *C.uint64_t) (err error) {
	arglist := (*C.struct_gocrypt_logstack)(nil)
	
	
	_kdf := C.CString(kdf)
	defer C.free(unsafe.Pointer(_kdf))
	
	
	
	_hash := C.CString(hash)
	defer C.free(unsafe.Pointer(_hash))
	
	
	
	_password := unsafe.Pointer(nil)
	if password != nil {
		_password = C.CBytes(password)
		defer C.free(_password)
	} else {
		
		panic("nil unexpected")
		
	}
	
	
	
	
	// not a pointer
	
	_password_size := (C.size_t)(len(password))
	
	
	
	_salt := unsafe.Pointer(nil)
	if salt != nil {
		_salt = C.CBytes(salt)
		defer C.free(_salt)
	} else {
		
		panic("nil unexpected")
		
	}
	
	
	
	
	// not a pointer
	
	_salt_size := (C.size_t)(len(salt))
	
	
	
	
	
	if iterations_sec == nil {
		panic("nil unexpected")
	}
	
	
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

