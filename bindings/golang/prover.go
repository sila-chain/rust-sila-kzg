package sila_kzg

/*
#cgo darwin,amd64 LDFLAGS: ./build/x86_64-apple-darwin/libc_sila_kzg.a
#cgo darwin,arm64 LDFLAGS: ./build/aarch64-apple-darwin/libc_sila_kzg.a
#cgo linux,amd64 LDFLAGS: ./build/x86_64-unknown-linux-gnu/libc_sila_kzg.a -lm
#cgo linux,arm64 LDFLAGS: ./build/aarch64-unknown-linux-gnu/libc_sila_kzg.a -lm
#cgo windows LDFLAGS: ./build/x86_64-pc-windows-gnu/libc_sila_kzg.a -lws2_32 -lntdll -luserenv
#include "./build/c_sila_kzg.h"
*/
import "C"
import (
	"errors"
	"runtime"
)

/*

NOTICE: This binding will not be maintained and is only for demonstration purposes.
		The main reason being that forcing downstream users and their dependents to install
		a rust toolchain is not ideal.
*/

const (
	// BytesPerCommitment is the number of bytes in a KZG commitment.
	BytesPerCommitment = 48

	// BytesPerProof is the number of bytes in a KZG proof.
	BytesPerProof = 48

	// BytesPerFieldElement is the number of bytes in a BLS scalar field element.
	BytesPerFieldElement = 32

	// BytesPerBlob is the number of bytes in a blob.
	BytesPerBlob = 131_072

	// MaxNumColumns is the maximum number of columns in an extended blob.
	MaxNumColumns = 128

	// BytesPerCell is the number of bytes in a single cell.
	BytesPerCell = 2048
)

type DASContext struct {
	_inner *C.DASContext
}

func NewProverContext() *DASContext {
	self := &DASContext{_inner: C.sila_kzg_das_context_new(C._Bool(true))}

	runtime.SetFinalizer(self, func(self *DASContext) {
		C.sila_kzg_das_context_free(self.inner())
	})

	return self
}

func (prover *DASContext) BlobToKZGCommitment(blob []byte) ([]byte, error) {
	if len(blob) != BytesPerBlob {
		return nil, errors.New("invalid blob size")
	}
	out := make([]byte, 48)
	C.sila_kzg_blob_to_kzg_commitment(prover.inner(), (*C.uint8_t)(&blob[0]), (*C.uint8_t)(&out[0]))
	return out, nil
}

func (prover *DASContext) inner() *C.DASContext {
	return prover._inner
}
