package cryptsetup

import (
	"fmt"
	"testing"
)

var message = []string{"a message from libcryptsetup"}

func TestNewError(t *testing.T) {
	testcodes := [][]int{
		[]int{0, 5},   // no error
		[]int{-1, -9}, // yes error
	}
	for tst := range testcodes {
		tst := tst
		for _, i := range testcodes[tst] {
			i := i
			t.Run(fmt.Sprint(i), func(t *testing.T) {
				for _, msg := range [][]string{nil, message} {
					msg := msg
					t.Run(fmt.Sprint(msg), func(t *testing.T) {
						t.Parallel()
						err := newError(i, msg)
						if (err != nil) == (tst == 0) {
							t.Fail()
						}
					})
				}
			})
		}
	}
}
