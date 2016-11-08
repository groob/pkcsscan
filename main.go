package main

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"reflect"
)

func main() {
	data, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	var funcs = []parseFunc{
		publicKey,
		pkcs8priv,
		pkcs1priv,
		cert,
	}
	scanAll(data, funcs...)
}

// asn1Sequence is the delimiter used to parse PKCS data.
var asn1sequence = []byte{48, 130}

// parseFunc is a function which can be used to parse
// some object from []byte.
type parseFunc func([]byte) (val interface{}, err error)

var (
	pkcs8priv parseFunc = x509.ParsePKCS8PrivateKey
	publicKey           = x509.ParsePKIXPublicKey
	pkcs1priv           = wrapPKCS1
	cert                = wrapCert
)

func wrapPKCS1(data []byte) (interface{}, error) {
	result, err := x509.ParsePKCS1PrivateKey(data)
	if result != nil && err == nil {
		return result, nil
	}
	return nil, err
}

func wrapCert(data []byte) (interface{}, error) {
	result, err := x509.ParseCertificate(data)
	if result != nil && err == nil {
		return result, nil
	}
	return nil, err
}

func scanAll(input []byte, funcs ...parseFunc) {
	for _, fn := range funcs {
		results := maybeFind(input, fn)
		for idx, kind := range results {
			fmt.Printf("found %s at index: %d\n", reflect.TypeOf(kind), idx)
		}
	}
}

func maybeFind(input []byte, fn parseFunc) map[int]interface{} {
	results := make(map[int]interface{})
	var result interface{}
	var data []byte
	data = input
	for {
		idx := bytes.Index(data, asn1sequence)
		if idx == -1 {
			break
		}
		result, data = withOffset(data, idx, fn)
		if result != nil {
			cursor := (len(input) - len(data) - 1)
			results[cursor] = result
		}
	}
	return results
}

func withOffset(data []byte, off int, fn parseFunc) (result interface{}, rest []byte) {
	offset := data[off:]
	var err error
	for i := 1; i <= len(offset); i++ {
		result, err = fn(offset[:i])
		if err == nil {
			break
		}
	}
	return result, offset[1:]
}
