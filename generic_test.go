package cryptsetup

import (
	"testing"
)

func TestNilHasZeroLength(t *testing.T) {
	if len([]byte(nil)) != 0 {
		t.Fail()
	}
}
