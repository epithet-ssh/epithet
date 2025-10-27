package netstr_test

import (
	"bytes"
	"fmt"
	"io"

	"github.com/epithet-ssh/epithet/pkg/netstr"
)

func ExampleEncoder_Encode() {
	var buf bytes.Buffer
	enc := netstr.NewEncoder(&buf)

	enc.Encode([]byte("hello"))
	enc.Encode([]byte("world"))

	fmt.Println(buf.String())
	// Output: 5:hello,5:world,
}

func ExampleEncoder_EncodeKeyed() {
	var buf bytes.Buffer
	enc := netstr.NewEncoder(&buf)

	enc.EncodeKeyed('t', []byte("my-token"))
	enc.EncodeKeyed('s', []byte(`{"refresh":"xyz"}`))

	fmt.Println(buf.String())
	// Output: 9:tmy-token,18:s{"refresh":"xyz"},
}

func ExampleDecoder_Decode() {
	data := []byte("5:hello,5:world,")
	dec := netstr.NewDecoder(bytes.NewReader(data))

	for {
		payload, err := dec.Decode()
		if err == io.EOF {
			break
		}
		if err != nil {
			panic(err)
		}
		fmt.Printf("%s\n", payload)
	}
	// Output:
	// hello
	// world
}

func ExampleDecoder_DecodeKeyed() {
	data := []byte("9:tmy-token,18:s{\"refresh\":\"xyz\"},")
	dec := netstr.NewDecoder(bytes.NewReader(data))

	for {
		key, value, err := dec.DecodeKeyed()
		if err == io.EOF {
			break
		}
		if err != nil {
			panic(err)
		}
		fmt.Printf("key=%c value=%s\n", key, value)
	}
	// Output:
	// key=t value=my-token
	// key=s value={"refresh":"xyz"}
}

func ExampleLenient() {
	// Simulates output from bash script using echo (adds newlines)
	data := []byte("5:hello,\n5:world,\n")
	dec := netstr.NewDecoder(bytes.NewReader(data), netstr.Lenient())

	for {
		payload, err := dec.Decode()
		if err == io.EOF {
			break
		}
		if err != nil {
			panic(err)
		}
		fmt.Printf("%s\n", payload)
	}
	// Output:
	// hello
	// world
}

func ExampleMaxLength() {
	// Limit netstring length to 100 bytes
	data := []byte("200:x") // Length exceeds limit
	dec := netstr.NewDecoder(bytes.NewReader(data), netstr.MaxLength(100))

	_, err := dec.Decode()
	if err == netstr.ErrTooLarge {
		fmt.Println("netstring too large")
	}
	// Output: netstring too large
}
