package main

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"reflect"
	"sync"
)

func main() {
	data, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	var wg sync.WaitGroup
	offsets := findOffsets(data, asn1sequence)
	for _, offset := range offsets {
		wg.Add(1)
		go func(at int) {
			defer wg.Done()
			maybeParse(data, at, cert)
		}(offset)
		go func(at int) {
			defer wg.Done()
			maybeParse(data, at, pkcs1priv)
		}(offset)
		go func(at int) {
			defer wg.Done()
			maybeParse(data, at, pkcs8priv)
		}(offset)
		go func(at int) {
			defer wg.Done()
			maybeParse(data, at, publicKey)
		}(offset)
	}
	wg.Wait()
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

func findOffsets(data []byte, delim []byte) []int {
	total := len(data)
	var all []int
	for {
		idx := bytes.Index(data, delim)
		if idx == -1 {
			break
		}
		data = data[idx+1:]
		cursor := (total - len(data) - 1)
		all = append(all, cursor)
	}
	return all
}

func withOffset(data []byte, off int, fn parseFunc) (result interface{}) {
	offset := data[off:]
	var err error
	for i := 1; i <= len(offset); i++ {
		result, err = fn(offset[:i])
		if err == nil {
			break
		}
	}
	return result
}

func maybeParse(data []byte, idx int, fn parseFunc) interface{} {
	result := withOffset(data, idx, fn)
	if result != nil {
		if certificate, ok := result.(*x509.Certificate); ok {
			fmt.Printf("found %s at index: %d, CN=%q \n", reflect.TypeOf(result), idx, certificate.Subject.CommonName)
		} else {
			fmt.Printf("found %s at index: %d\n", reflect.TypeOf(result), idx)
		}
		return result
	}
	return nil
}
