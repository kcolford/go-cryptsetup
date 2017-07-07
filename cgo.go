package cryptsetup

// #include <stdlib.h>
import "C"
import (
	"unsafe"
)

func cString(str string) *C.char {
	if str == "" {
		return nil
	}
	return C.CString(str)
}

func cStringFree(str *C.char) {
	if str != nil {
		C.free(unsafe.Pointer(str))
	}
}

func cBytes(buf []byte) unsafe.Pointer {
	if buf == nil {
		return nil
	}
	return C.CBytes(buf)
}

func cBytesFree(buf unsafe.Pointer) {
	if buf != nil {
		C.free(buf)
	}
}
