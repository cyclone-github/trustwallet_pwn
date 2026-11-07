// Copyright (c) 2012 The Go Authors. All rights reserved.
//
// Adapted from golang.org/x/crypto/scrypt to support per-worker scratch
// reuse. See THIRD_PARTY_SCRYPT_LICENSE.txt for license terms.

package main

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/bits"
)

type scryptScratch struct {
	xy []uint32
	v  []uint32
	b  []byte
}

func (s *scryptScratch) reset(N, r, p int) error {
	if N <= 1 || N&(N-1) != 0 {
		return errors.New("scrypt: N must be > 1 and a power of 2")
	}
	if r <= 0 || p <= 0 {
		return errors.New("scrypt: parameters must be > 0")
	}
	xyLen := 64 * r
	vLen := 32 * N * r
	bLen := p * 128 * r
	if cap(s.xy) < xyLen {
		s.xy = make([]uint32, xyLen)
	} else {
		s.xy = s.xy[:xyLen]
	}
	if cap(s.v) < vLen {
		s.v = make([]uint32, vLen)
	} else {
		s.v = s.v[:vLen]
	}
	if cap(s.b) < bLen {
		s.b = make([]byte, bLen)
	} else {
		s.b = s.b[:bLen]
	}
	return nil
}

func scryptBlockCopy(dst, src []uint32, n int) {
	copy(dst, src[:n])
}

func scryptBlockXOR(dst, src []uint32, n int) {
	for i, v := range src[:n] {
		dst[i] ^= v
	}
}

func scryptSalsaXOR(tmp *[16]uint32, in, out []uint32) {
	w0 := tmp[0] ^ in[0]
	w1 := tmp[1] ^ in[1]
	w2 := tmp[2] ^ in[2]
	w3 := tmp[3] ^ in[3]
	w4 := tmp[4] ^ in[4]
	w5 := tmp[5] ^ in[5]
	w6 := tmp[6] ^ in[6]
	w7 := tmp[7] ^ in[7]
	w8 := tmp[8] ^ in[8]
	w9 := tmp[9] ^ in[9]
	w10 := tmp[10] ^ in[10]
	w11 := tmp[11] ^ in[11]
	w12 := tmp[12] ^ in[12]
	w13 := tmp[13] ^ in[13]
	w14 := tmp[14] ^ in[14]
	w15 := tmp[15] ^ in[15]

	x0, x1, x2, x3, x4, x5, x6, x7, x8 := w0, w1, w2, w3, w4, w5, w6, w7, w8
	x9, x10, x11, x12, x13, x14, x15 := w9, w10, w11, w12, w13, w14, w15

	for i := 0; i < 8; i += 2 {
		x4 ^= bits.RotateLeft32(x0+x12, 7)
		x8 ^= bits.RotateLeft32(x4+x0, 9)
		x12 ^= bits.RotateLeft32(x8+x4, 13)
		x0 ^= bits.RotateLeft32(x12+x8, 18)

		x9 ^= bits.RotateLeft32(x5+x1, 7)
		x13 ^= bits.RotateLeft32(x9+x5, 9)
		x1 ^= bits.RotateLeft32(x13+x9, 13)
		x5 ^= bits.RotateLeft32(x1+x13, 18)

		x14 ^= bits.RotateLeft32(x10+x6, 7)
		x2 ^= bits.RotateLeft32(x14+x10, 9)
		x6 ^= bits.RotateLeft32(x2+x14, 13)
		x10 ^= bits.RotateLeft32(x6+x2, 18)

		x3 ^= bits.RotateLeft32(x15+x11, 7)
		x7 ^= bits.RotateLeft32(x3+x15, 9)
		x11 ^= bits.RotateLeft32(x7+x3, 13)
		x15 ^= bits.RotateLeft32(x11+x7, 18)

		x1 ^= bits.RotateLeft32(x0+x3, 7)
		x2 ^= bits.RotateLeft32(x1+x0, 9)
		x3 ^= bits.RotateLeft32(x2+x1, 13)
		x0 ^= bits.RotateLeft32(x3+x2, 18)

		x6 ^= bits.RotateLeft32(x5+x4, 7)
		x7 ^= bits.RotateLeft32(x6+x5, 9)
		x4 ^= bits.RotateLeft32(x7+x6, 13)
		x5 ^= bits.RotateLeft32(x4+x7, 18)

		x11 ^= bits.RotateLeft32(x10+x9, 7)
		x8 ^= bits.RotateLeft32(x11+x10, 9)
		x9 ^= bits.RotateLeft32(x8+x11, 13)
		x10 ^= bits.RotateLeft32(x9+x8, 18)

		x12 ^= bits.RotateLeft32(x15+x14, 7)
		x13 ^= bits.RotateLeft32(x12+x15, 9)
		x14 ^= bits.RotateLeft32(x13+x12, 13)
		x15 ^= bits.RotateLeft32(x14+x13, 18)
	}
	x0 += w0
	x1 += w1
	x2 += w2
	x3 += w3
	x4 += w4
	x5 += w5
	x6 += w6
	x7 += w7
	x8 += w8
	x9 += w9
	x10 += w10
	x11 += w11
	x12 += w12
	x13 += w13
	x14 += w14
	x15 += w15

	out[0], tmp[0] = x0, x0
	out[1], tmp[1] = x1, x1
	out[2], tmp[2] = x2, x2
	out[3], tmp[3] = x3, x3
	out[4], tmp[4] = x4, x4
	out[5], tmp[5] = x5, x5
	out[6], tmp[6] = x6, x6
	out[7], tmp[7] = x7, x7
	out[8], tmp[8] = x8, x8
	out[9], tmp[9] = x9, x9
	out[10], tmp[10] = x10, x10
	out[11], tmp[11] = x11, x11
	out[12], tmp[12] = x12, x12
	out[13], tmp[13] = x13, x13
	out[14], tmp[14] = x14, x14
	out[15], tmp[15] = x15, x15
}

func scryptBlockMix(tmp *[16]uint32, in, out []uint32, r int) {
	scryptBlockCopy(tmp[:], in[(2*r-1)*16:], 16)
	for i := 0; i < 2*r; i += 2 {
		scryptSalsaXOR(tmp, in[i*16:], out[i*8:])
		scryptSalsaXOR(tmp, in[i*16+16:], out[i*8+r*16:])
	}
}

func scryptInteger(b []uint32, r int) uint64 {
	j := (2*r - 1) * 16
	return uint64(b[j]) | uint64(b[j+1])<<32
}

func scryptSmix(b []byte, r, N int, v, xy []uint32) {
	var tmp [16]uint32
	R := 32 * r
	x := xy
	y := xy[R:]

	j := 0
	for i := 0; i < R; i++ {
		x[i] = binary.LittleEndian.Uint32(b[j:])
		j += 4
	}
	for i := 0; i < N; i += 2 {
		scryptBlockCopy(v[i*R:], x, R)
		scryptBlockMix(&tmp, x, y, r)

		scryptBlockCopy(v[(i+1)*R:], y, R)
		scryptBlockMix(&tmp, y, x, r)
	}
	for i := 0; i < N; i += 2 {
		j := int(scryptInteger(x, r) & uint64(N-1))
		scryptBlockXOR(x, v[j*R:], R)
		scryptBlockMix(&tmp, x, y, r)

		j = int(scryptInteger(y, r) & uint64(N-1))
		scryptBlockXOR(y, v[j*R:], R)
		scryptBlockMix(&tmp, y, x, r)
	}
	j = 0
	for _, v := range x[:R] {
		binary.LittleEndian.PutUint32(b[j:], v)
		j += 4
	}
}

// cpuScryptKey matches golang.org/x/crypto/scrypt.Key output for identical inputs.
func cpuScryptKey(ws *cpuWorkerScratch, password, salt []byte, N, r, p, keyLen int) ([]byte, error) {
	const maxInt = int(^uint(0) >> 1)
	if N <= 1 || N&(N-1) != 0 || r <= 0 || p <= 0 || keyLen <= 0 {
		return nil, errors.New("scrypt: invalid parameters")
	}
	if uint64(r)*uint64(p) >= 1<<30 || r > maxInt/128/p || r > maxInt/256 || N > maxInt/128/r {
		return nil, errors.New("scrypt: parameters are too large")
	}
	scratch := &ws.scrypt
	if err := scratch.reset(N, r, p); err != nil {
		return nil, err
	}
	if err := pbkdf2KeyInto(scratch.b, password, salt, 1, sha256.New, ws.pbkdf2U[:], ws.pbkdf2T[:]); err != nil {
		return nil, err
	}
	for i := 0; i < p; i++ {
		scryptSmix(scratch.b[i*128*r:], r, N, scratch.v, scratch.xy)
	}
	if keyLen > len(ws.scryptOut) {
		out := make([]byte, keyLen)
		if err := pbkdf2KeyInto(out, password, scratch.b, 1, sha256.New, ws.pbkdf2U[:], ws.pbkdf2T[:]); err != nil {
			return nil, err
		}
		return out, nil
	}
	if err := pbkdf2KeyInto(ws.scryptOut[:keyLen], password, scratch.b, 1, sha256.New, ws.pbkdf2U[:], ws.pbkdf2T[:]); err != nil {
		return nil, err
	}
	return append([]byte(nil), ws.scryptOut[:keyLen]...), nil
}
