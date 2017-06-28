package main

import (
	"testing"
)

func TestBasic(t *testing.T) {
	_, err := Templates("./templates/")
	if err != nil {
		t.Error(err)
	}
}
