package cryptsetup

import (
	"fmt"
	"strings"
	"syscall"
)

// CryptError is an error produced by libcryptsetup.
type CryptError struct {
	Messages []string
	Errno    error
}

func (e CryptError) Error() string {
	return fmt.Sprintf("%s: %v", e.Errno, strings.Join(e.Messages, ""))
}

// newError creates a CryptError if the return value of a library
// function indicates an error.
func newError(negerrno int, messages []string) error {
	if negerrno < 0 {
		return CryptError{
			Messages: messages,
			Errno:    syscall.Errno(-negerrno),
		}
	}
	return nil
}
