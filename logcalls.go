package cryptsetup

// #cgo pkg-config: libcryptsetup
// #include <libcryptsetup.h>
// #include <stdlib.h>
// #include "gocryptsetup.h"
// #include "logcalls.h"
// void gocrypt_log_default(int, char *, void *);
import "C"
import (
	"unsafe"
	"log"
)

// Setup a default logging function that uses the standard logger.
func init() {
	C.crypt_set_log_callback(
		nil,
		(*[0]byte)(C.gocrypt_log_default),
		nil,
	)
}
//export gocrypt_log_default
func gocrypt_log_default(level C.int, msg *C.char, usrptr unsafe.Pointer) {
	log.Print(C.GoString(msg))
}





func (d Device) formatLuks() (err error) {
	arglist := (*C.struct_gocrypt_logstack)(nil)
	
	
	ival := C.gocrypt_gocrypt_format_luks(
		&arglist,
		d.cd,
		)
	defer C.gocrypt_logstack_free(arglist)
	
	msg := ""
	for i := arglist; i != nil; i = i.prev {
		msg = C.GoString(i.message) + "\n" + msg
	}
	if ival < 0 {
		err = newError(int(ival), msg)
		return
	}
	
	
	return
}

func (d Device) setDataDevice(device string) (err error) {
	arglist := (*C.struct_gocrypt_logstack)(nil)
	
	
	_device := C.CString(device)
	defer C.free(unsafe.Pointer(_device))
	
	
	
	ival := C.gocrypt_crypt_set_data_device(
		&arglist,
		d.cd,
		
		_device,
		)
	defer C.gocrypt_logstack_free(arglist)
	
	msg := ""
	for i := arglist; i != nil; i = i.prev {
		msg = C.GoString(i.message) + "\n" + msg
	}
	if ival < 0 {
		err = newError(int(ival), msg)
		return
	}
	
	
	return
}

func (d Device) getRngType() (out int, err error) {
	arglist := (*C.struct_gocrypt_logstack)(nil)
	
	
	ival := C.gocrypt_crypt_get_rng_type(
		&arglist,
		d.cd,
		)
	defer C.gocrypt_logstack_free(arglist)
	
	msg := ""
	for i := arglist; i != nil; i = i.prev {
		msg = C.GoString(i.message) + "\n" + msg
	}
	if ival < 0 {
		err = newError(int(ival), msg)
		return
	}
	
	out = (int)(ival)
	return
}

func (d Device) setUuid(uuid string) (err error) {
	arglist := (*C.struct_gocrypt_logstack)(nil)
	
	
	_uuid := C.CString(uuid)
	defer C.free(unsafe.Pointer(_uuid))
	
	
	
	ival := C.gocrypt_crypt_set_uuid(
		&arglist,
		d.cd,
		
		_uuid,
		)
	defer C.gocrypt_logstack_free(arglist)
	
	msg := ""
	for i := arglist; i != nil; i = i.prev {
		msg = C.GoString(i.message) + "\n" + msg
	}
	if ival < 0 {
		err = newError(int(ival), msg)
		return
	}
	
	
	return
}

func (d Device) keyslotAddByPassphrase(keyslot int, passphrase []byte, new_passphrase []byte) (out int, err error) {
	arglist := (*C.struct_gocrypt_logstack)(nil)
	
	
	_keyslot := C.int(keyslot)
	
	
	
	_passphrase := unsafe.Pointer(nil)
	if passphrase != nil {
		_passphrase = C.CBytes(passphrase)
		defer C.free(_passphrase)
	}
	
	
	
	_passphrase_size := C.size_t(len(passphrase))
	
	
	
	_new_passphrase := unsafe.Pointer(nil)
	if new_passphrase != nil {
		_new_passphrase = C.CBytes(new_passphrase)
		defer C.free(_new_passphrase)
	}
	
	
	
	_new_passphrase_size := C.size_t(len(new_passphrase))
	
	
	
	ival := C.gocrypt_crypt_keyslot_add_by_passphrase(
		&arglist,
		d.cd,
		
		_keyslot,
		
		_passphrase,
		
		_passphrase_size,
		
		_new_passphrase,
		
		_new_passphrase_size,
		)
	defer C.gocrypt_logstack_free(arglist)
	
	msg := ""
	for i := arglist; i != nil; i = i.prev {
		msg = C.GoString(i.message) + "\n" + msg
	}
	if ival < 0 {
		err = newError(int(ival), msg)
		return
	}
	
	out = (int)(ival)
	return
}

func (d Device) keyslotChangeByPassphrase(keyslot_old int, keyslot_new int, passphrase []byte, new_passphrase []byte) (out int, err error) {
	arglist := (*C.struct_gocrypt_logstack)(nil)
	
	
	_keyslot_old := C.int(keyslot_old)
	
	
	
	_keyslot_new := C.int(keyslot_new)
	
	
	
	_passphrase := unsafe.Pointer(nil)
	if passphrase != nil {
		_passphrase = C.CBytes(passphrase)
		defer C.free(_passphrase)
	}
	
	
	
	_passphrase_size := C.size_t(len(passphrase))
	
	
	
	_new_passphrase := unsafe.Pointer(nil)
	if new_passphrase != nil {
		_new_passphrase = C.CBytes(new_passphrase)
		defer C.free(_new_passphrase)
	}
	
	
	
	_new_passphrase_size := C.size_t(len(new_passphrase))
	
	
	
	ival := C.gocrypt_crypt_keyslot_change_by_passphrase(
		&arglist,
		d.cd,
		
		_keyslot_old,
		
		_keyslot_new,
		
		_passphrase,
		
		_passphrase_size,
		
		_new_passphrase,
		
		_new_passphrase_size,
		)
	defer C.gocrypt_logstack_free(arglist)
	
	msg := ""
	for i := arglist; i != nil; i = i.prev {
		msg = C.GoString(i.message) + "\n" + msg
	}
	if ival < 0 {
		err = newError(int(ival), msg)
		return
	}
	
	out = (int)(ival)
	return
}

func (d Device) keyslotAddByKeyfileOffset(keyslot int, keyfile string, keyfile_size uint64, keyfile_offset uint64, new_keyfile string, new_keyfile_size uint64, new_keyfile_offset uint64) (err error) {
	arglist := (*C.struct_gocrypt_logstack)(nil)
	
	
	_keyslot := C.int(keyslot)
	
	
	
	_keyfile := C.CString(keyfile)
	defer C.free(unsafe.Pointer(_keyfile))
	
	
	
	_keyfile_size := C.size_t(keyfile_size)
	
	
	
	_keyfile_offset := C.size_t(keyfile_offset)
	
	
	
	_new_keyfile := C.CString(new_keyfile)
	defer C.free(unsafe.Pointer(_new_keyfile))
	
	
	
	_new_keyfile_size := C.size_t(new_keyfile_size)
	
	
	
	_new_keyfile_offset := C.size_t(new_keyfile_offset)
	
	
	
	ival := C.gocrypt_crypt_keyslot_add_by_keyfile_offset(
		&arglist,
		d.cd,
		
		_keyslot,
		
		_keyfile,
		
		_keyfile_size,
		
		_keyfile_offset,
		
		_new_keyfile,
		
		_new_keyfile_size,
		
		_new_keyfile_offset,
		)
	defer C.gocrypt_logstack_free(arglist)
	
	msg := ""
	for i := arglist; i != nil; i = i.prev {
		msg = C.GoString(i.message) + "\n" + msg
	}
	if ival < 0 {
		err = newError(int(ival), msg)
		return
	}
	
	
	return
}

func (d Device) keyslotAddByVolumeKey(keyslot int, volume_key []byte, passphrase []byte) (out int, err error) {
	arglist := (*C.struct_gocrypt_logstack)(nil)
	
	
	_keyslot := C.int(keyslot)
	
	
	
	_volume_key := unsafe.Pointer(nil)
	if volume_key != nil {
		_volume_key = C.CBytes(volume_key)
		defer C.free(_volume_key)
	}
	
	
	
	_volume_key_size := C.size_t(len(volume_key))
	
	
	
	_passphrase := unsafe.Pointer(nil)
	if passphrase != nil {
		_passphrase = C.CBytes(passphrase)
		defer C.free(_passphrase)
	}
	
	
	
	_passphrase_size := C.size_t(len(passphrase))
	
	
	
	ival := C.gocrypt_crypt_keyslot_add_by_volume_key(
		&arglist,
		d.cd,
		
		_keyslot,
		
		_volume_key,
		
		_volume_key_size,
		
		_passphrase,
		
		_passphrase_size,
		)
	defer C.gocrypt_logstack_free(arglist)
	
	msg := ""
	for i := arglist; i != nil; i = i.prev {
		msg = C.GoString(i.message) + "\n" + msg
	}
	if ival < 0 {
		err = newError(int(ival), msg)
		return
	}
	
	out = (int)(ival)
	return
}

func (d Device) keyslotDestroy(keyslot int) (err error) {
	arglist := (*C.struct_gocrypt_logstack)(nil)
	
	
	_keyslot := C.int(keyslot)
	
	
	
	ival := C.gocrypt_crypt_keyslot_destroy(
		&arglist,
		d.cd,
		
		_keyslot,
		)
	defer C.gocrypt_logstack_free(arglist)
	
	msg := ""
	for i := arglist; i != nil; i = i.prev {
		msg = C.GoString(i.message) + "\n" + msg
	}
	if ival < 0 {
		err = newError(int(ival), msg)
		return
	}
	
	
	return
}

func (d Device) activateByPassphrase(name string, keyslot int, passphrase []byte, flags uint32) (out int, err error) {
	arglist := (*C.struct_gocrypt_logstack)(nil)
	
	
	_name := C.CString(name)
	defer C.free(unsafe.Pointer(_name))
	
	
	
	_keyslot := C.int(keyslot)
	
	
	
	_passphrase := unsafe.Pointer(nil)
	if passphrase != nil {
		_passphrase = C.CBytes(passphrase)
		defer C.free(_passphrase)
	}
	
	
	
	_passphrase_size := C.size_t(len(passphrase))
	
	
	
	_flags := C.uint32_t(flags)
	
	
	
	ival := C.gocrypt_crypt_activate_by_passphrase(
		&arglist,
		d.cd,
		
		_name,
		
		_keyslot,
		
		_passphrase,
		
		_passphrase_size,
		
		_flags,
		)
	defer C.gocrypt_logstack_free(arglist)
	
	msg := ""
	for i := arglist; i != nil; i = i.prev {
		msg = C.GoString(i.message) + "\n" + msg
	}
	if ival < 0 {
		err = newError(int(ival), msg)
		return
	}
	
	out = (int)(ival)
	return
}

