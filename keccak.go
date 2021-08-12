package keccak

import (
	"encoding/binary"
	"hash"
	"math/bits"
)

const (
	domainNone  = 0x01
	domainSha3  = 0x06
	domainShake = 0x1f
)

type keccak struct {
	a         [25]uint64
	x       [25 * 8]byte
	nx 		  int
	size      int
	blockSize int	//rate
	domain    byte
}

func newKeccak(capacityBits, sizeBits int, domain byte) hash.Hash {
	var h keccak
	h.size = sizeBits / 8
	h.blockSize = 25 * 8 - capacityBits / 8
	h.domain = domain
	return &h
}


func (k *keccak) Size() int {
	return k.size
}

func (k *keccak) BlockSize() int {
	return k.blockSize
}

func (k *keccak) Reset() {
	for i := range k.a {
		k.a[i] = 0
	}
	k.nx = 0
}

func (d *keccak) Write(p []byte) (nn int, err error) {
	ns := len(p)
	nn = ns
	if d.nx > 0 {
		n := copy(d.x[d.nx:], p)
		d.nx += n
		if d.nx < d.blockSize {
			return
		} else {
			d.nx = 0
			block(d, d.x[:], 1)
			p = p[n:]
			ns -= n
		}
	}
	blocks := uint64(ns / d.blockSize)
	block(d, p[:], blocks)
	p = p[blocks * uint64(d.blockSize):]

	d.nx = copy(d.x[:], p)
	return
}

func (d *keccak) Sum(in []byte) []byte {
	// Make a copy of d so that caller can keep writing and summing.
	d0 := *d
	return d0.checkSum(in)
}

var zeros [25 * 8]byte
func (d *keccak) checkSum(in []byte) []byte {
	d.x[d.nx] = d.domain
	copy(d.x[d.nx+1:], zeros[:])
	d.x[d.blockSize - 1] |= 0x80
	block(d, d.x[:], 1)

	p := in
	if d.size != 0 {
		p = make([]byte, d.size)
	}
	q := p
	if d.size == 0 {
		q = nil
	}

	blob := make([]byte, d.blockSize)
	for len(p) > 0 {
		for i := 0; i < d.blockSize / 8; i++ {
			binary.LittleEndian.PutUint64(blob[i * 8 :], d.a[i])
		}
		n := copy(p, blob)
		p = p[n:]
		keccakF1600(&d.a)
	}
	return append(in, q...)
}


func block(d *keccak, q []byte, blocks uint64) {
	for i := 0; i < int(blocks); i++ {
		p := q[i * d.blockSize:]
		for j := 0; j < d.blockSize / 8; j++ {
			d.a[j] ^= binary.LittleEndian.Uint64(p[j * 8:])
		}
		keccakF1600(&d.a)
	}
}

func keccakf(A *[25]uint64){
	keccakF1600(A)
}
func keccakF1600(A *[25]uint64){
	a00 := A[ 0]; a01 := A[ 1]; a02 := A[ 2]; a03 := A[ 3]; a04 := A[ 4];
	a05 := A[ 5]; a06 := A[ 6]; a07 := A[ 7]; a08 := A[ 8]; a09 := A[ 9];
	a10 := A[10]; a11 := A[11]; a12 := A[12]; a13 := A[13]; a14 := A[14];
	a15 := A[15]; a16 := A[16]; a17 := A[17]; a18 := A[18]; a19 := A[19];
	a20 := A[20]; a21 := A[21]; a22 := A[22]; a23 := A[23]; a24 := A[24];

	for i := 0; i < 24; i++{
		c0 := a00 ^ a05 ^ a10 ^ a15 ^ a20;
		c1 := a01 ^ a06 ^ a11 ^ a16 ^ a21;
		c2 := a02 ^ a07 ^ a12 ^ a17 ^ a22;
		c3 := a03 ^ a08 ^ a13 ^ a18 ^ a23;
		c4 := a04 ^ a09 ^ a14 ^ a19 ^ a24;

		d1 := bits.RotateLeft64(c1, 1) ^ c4;
		d2 := bits.RotateLeft64(c2, 1) ^ c0;
		d3 := bits.RotateLeft64(c3, 1) ^ c1;
		d4 := bits.RotateLeft64(c4, 1) ^ c2;
		d0 := bits.RotateLeft64(c0, 1) ^ c3;

		a00 ^= d1; a05 ^= d1; a10 ^= d1; a15 ^= d1; a20 ^= d1;
		a01 ^= d2; a06 ^= d2; a11 ^= d2; a16 ^= d2; a21 ^= d2;
		a02 ^= d3; a07 ^= d3; a12 ^= d3; a17 ^= d3; a22 ^= d3;
		a03 ^= d4; a08 ^= d4; a13 ^= d4; a18 ^= d4; a23 ^= d4;
		a04 ^= d0; a09 ^= d0; a14 ^= d0; a19 ^= d0; a24 ^= d0;

		// rho/pi
		c1  = bits.RotateLeft64(a01, 1);
		a01 = bits.RotateLeft64(a06, 44);
		a06 = bits.RotateLeft64(a09, 20);
		a09 = bits.RotateLeft64(a22, 61);
		a22 = bits.RotateLeft64(a14, 39);
		a14 = bits.RotateLeft64(a20, 18);
		a20 = bits.RotateLeft64(a02, 62);
		a02 = bits.RotateLeft64(a12, 43);
		a12 = bits.RotateLeft64(a13, 25);
		a13 = bits.RotateLeft64(a19, 8);
		a19 = bits.RotateLeft64(a23, 56);
		a23 = bits.RotateLeft64(a15, 41);
		a15 = bits.RotateLeft64(a04, 27);
		a04 = bits.RotateLeft64(a24, 14);
		a24 = bits.RotateLeft64(a21, 2);
		a21 = bits.RotateLeft64(a08, 55);
		a08 = bits.RotateLeft64(a16, 45);
		a16 = bits.RotateLeft64(a05, 36);
		a05 = bits.RotateLeft64(a03, 28);
		a03 = bits.RotateLeft64(a18, 21);
		a18 = bits.RotateLeft64(a17, 15);
		a17 = bits.RotateLeft64(a11, 10);
		a11 = bits.RotateLeft64(a07, 6);
		a07 = bits.RotateLeft64(a10, 3);
		a10 = c1;

		// chi
		c0 = a00 ^ (^a01 & a02);
		c1 = a01 ^ (^a02 & a03);
		a02 ^= ^a03 & a04;
		a03 ^= ^a04 & a00;
		a04 ^= ^a00 & a01;
		a00 = c0;
		a01 = c1;

		c0 = a05 ^ (^a06 & a07);
		c1 = a06 ^ (^a07 & a08);
		a07 ^= ^a08 & a09;
		a08 ^= ^a09 & a05;
		a09 ^= ^a05 & a06;
		a05 = c0;
		a06 = c1;

		c0 = a10 ^ (^a11 & a12);
		c1 = a11 ^ (^a12 & a13);
		a12 ^= ^a13 & a14;
		a13 ^= ^a14 & a10;
		a14 ^= ^a10 & a11;
		a10 = c0;
		a11 = c1;

		c0 = a15 ^ (^a16 & a17);
		c1 = a16 ^ (^a17 & a18);
		a17 ^= ^a18 & a19;
		a18 ^= ^a19 & a15;
		a19 ^= ^a15 & a16;
		a15 = c0;
		a16 = c1;

		c0 = a20 ^ (^a21 & a22);
		c1 = a21 ^ (^a22 & a23);
		a22 ^= ^a23 & a24;
		a23 ^= ^a24 & a20;
		a24 ^= ^a20 & a21;
		a20 = c0;
		a21 = c1;

		// iota
		a00 ^= rc[i];
	}

	A[ 0] = a00; A[ 1] = a01; A[ 2] = a02; A[ 3] = a03; A[ 4] = a04;
	A[ 5] = a05; A[ 6] = a06; A[ 7] = a07; A[ 8] = a08; A[ 9] = a09;
	A[10] = a10; A[11] = a11; A[12] = a12; A[13] = a13; A[14] = a14;
	A[15] = a15; A[16] = a16; A[17] = a17; A[18] = a18; A[19] = a19;
	A[20] = a20; A[21] = a21; A[22] = a22; A[23] = a23; A[24] = a24;
}


var rc = []uint64{
	0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
	0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
	0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
	0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
	0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
}
