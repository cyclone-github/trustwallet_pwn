package main

import (
	"crypto/sha512"
	"encoding/hex"
	"sync"
)

const (
	presaltPassLen = 2 + 1024 // "0x" + 512-byte hex for trust:pbkdf2
	presaltDKLen   = 512
	trustScryptN   = 16384
	trustScryptR   = 8
	trustScryptP   = 4
)

type cpuWorkerScratch struct {
	presaltPass []byte
	presaltDK   [presaltDKLen]byte
	pbkdf2U     [64]byte
	pbkdf2T     [64]byte
	scryptOut   [32]byte
	scrypt      scryptScratch
}

var cpuWorkerScratchPool sync.Pool

func init() {
	cpuWorkerScratchPool.New = func() any { return newCPUWorkerScratch() }
}

func newCPUWorkerScratch() *cpuWorkerScratch {
	s := &cpuWorkerScratch{presaltPass: make([]byte, presaltPassLen)}
	return s
}

func acquireCPUScratch() *cpuWorkerScratch {
	v, ok := cpuWorkerScratchPool.Get().(*cpuWorkerScratch)
	if !ok || v == nil {
		v = newCPUWorkerScratch()
	}
	return v
}

func releaseCPUScratch(s *cpuWorkerScratch) {
	cpuWorkerScratchPool.Put(s)
}

func (s *cpuWorkerScratch) transformedPassword(v vault, pw []byte) ([]byte, error) {
	if v.presalt == nil {
		return pw, nil
	}
	if err := pbkdf2KeyInto(s.presaltDK[:], pw, v.presalt, 20000, sha512.New, s.pbkdf2U[:], s.pbkdf2T[:]); err != nil {
		return nil, err
	}
	pass := s.presaltPass
	need := 2 + hex.EncodedLen(presaltDKLen)
	if cap(pass) < need {
		pass = make([]byte, need)
		s.presaltPass = pass
	}
	pass = pass[:need]
	pass[0], pass[1] = '0', 'x'
	hex.Encode(pass[2:], s.presaltDK[:])
	return pass, nil
}
