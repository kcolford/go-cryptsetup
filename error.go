package cryptsetup

import (
	"syscall"
)

// CryptError is an error produced by libcryptsetup.
type CryptError struct {
	Message string
	Level   int
	Method  string
	Errno   error
}

func (e CryptError) Error() string {
	if e.Method == "" {
		return e.Message
	} else {
		return e.Method + ": " + e.Message
	}
}

func newError(negerrno int, message string) error {
	if negerrno < 0 {
		return CryptError{
			Message: message,
			Errno:   syscall.Errno(-negerrno),
		}
	}
	return nil
}
