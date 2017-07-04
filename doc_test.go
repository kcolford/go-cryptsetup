package cryptsetup

import (
	"fmt"
)

func ExampleDevice_Benchmark() {
	d, err := NewDevice("/dev/sda")
	if err != nil {
		panic(err)
	}
	defer d.Close()

	enc, dec, err := d.Benchmark(128, 4096)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Encryption time: %f MiB/s\n", enc)
	fmt.Printf("Decryption time: %f MiB/s\n", dec)
}

func ExampleDevice_BenchmarkKdf() {
	d, err := NewDevice("/dev/sda")
	if err != nil {
		panic(err)
	}
	defer d.Close()

	iter, err := d.BenchmarkKdf([]byte("my password"), []byte("secure salt"))
	if err != nil {
		panic(err)
	}
	fmt.Printf("Kdf iterations per second: %d\n", iter)
}
