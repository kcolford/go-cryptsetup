package cryptsetup

// #cgo pkg-config: libcryptsetup
// #include <libcryptsetup.h>
// #include "log.h"
// #include <stdlib.h>
import "C"
import (
	"log"
	"unsafe"
)

// Setup a default logging function that uses the standard logger.
func init() {
	C.crypt_set_log_callback(
		nil,
		(*[0]byte)(C.gocrypt_log_default),
		nil,
	)
}

//export golang_gocrypt_log_default
func golang_gocrypt_log_default(msg *C.char) {
	log.Print(C.GoString(msg))
}

//export golang_gocrypt_log
func golang_gocrypt_log(msg *C.char, ls **C.struct_gocrypt_logstack) {
	if ls == nil {
		panic("nil value passed as reference")
	}
	out := (*C.struct_gocrypt_logstack)(C.malloc(C.sizeof_struct_gocrypt_logstack))
	out.message = C.CString(C.GoString(msg))
	out.prev = *ls
	*ls = out
}

func logMessages(ls *C.struct_gocrypt_logstack) []string {
	if ls == nil {
		return nil
	}
	defer C.free(unsafe.Pointer(ls.message))
	defer C.free(unsafe.Pointer(ls))
	return append(logMessages(ls.prev), C.GoString(ls.message))
}
