/*
 * Copyright (c) 2025, Marc Himmelberger <marc dot himmelberger at inf dot ethz dot ch>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  * Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package encoding_hqc

import (
	"crypto/sha3"
	"fmt"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/csrand"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/cryptofactory/filter_encode"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/kems"
)

// size of seed1 and seed2 in bytes
const seedSize int = 40

// An encoder for HQC that forces the ciphertext parity u(1) to 0 by rejecting public keys (if necessary),
// and that adds 4-6 extra random bits to every ciphertext in order to make all components byte-aligned.
type HqcEncoder struct {
	forcePkParity bool // true iff public keys with h(1)=0 should be rejected
	numBytesPoly  int  // number of bytes taken up by the "h" and "u" polynomials in HQC
	sizeCt        int  // size of HQC ciphertexts
	maskEmpty     byte // bitmask for the final byte of HQC polynomials, selecting always-empty bits
	maskUsed      byte // bitmask for the final byte of HQC polynomials, selecting used bits
	maskLast      byte // bitmask for the final byte of HQC polynomials, selecting the last used bit
	maskRand      byte // bitmask for the final byte of HQC polynomials, selecting bits to randomize
}

func (encoder *HqcEncoder) getParity(data []byte) byte {
	polySlice := data[:encoder.numBytesPoly]
	var acc byte
	for i, b := range polySlice {
		if i == encoder.numBytesPoly-1 {
			acc ^= b & encoder.maskUsed
		} else {
			acc ^= b
		}
	}
	acc ^= acc >> 4
	acc ^= acc >> 2
	acc ^= acc >> 1
	return acc & 0x01
}

// Performs the "seedexpander" function from the HQC specification.
// Turns a seed of size seedSize into a suitably sized polynomial.
func (encoder *HqcEncoder) seedexpander(seed []byte) []byte {
	if len(seed) != seedSize {
		panic(fmt.Sprintf("BUG: Invalid seed size for seedexpander. expected: %d, actual: %d", seedSize, len(seed)))
	}

	// See Reference Implementation's shake_prng.cpp
	var domain [1]byte = [1]byte{0x02}
	state := sha3.NewSHAKE256()
	state.Write(seed)
	state.Write(domain[:])

	polyOut := make([]byte, encoder.numBytesPoly)

	state.Read(polyOut)
	// Remove unused bits from very last byte
	polyOut[encoder.numBytesPoly-1] &= encoder.maskUsed

	return polyOut
}

func (encoder *HqcEncoder) Init(kem kems.KeyEncapsulationMechanism) {
	// nmumber of bits ordinarily used for HQC polynomials in the last byte
	var lastByteUsed int

	switch kem.Name() {
	case "HQC-128":
		encoder.forcePkParity = true
		encoder.numBytesPoly = 2209
		encoder.sizeCt = 4433
		lastByteUsed = 5
	case "HQC-192":
		encoder.forcePkParity = false
		encoder.numBytesPoly = 4482
		encoder.sizeCt = 8978
		lastByteUsed = 3
	case "HQC-256":
		encoder.forcePkParity = true
		encoder.numBytesPoly = 7205
		encoder.sizeCt = 14421
		lastByteUsed = 5
	default:
		panic("encoding_hqc: This encoder is only applicable for HQC KEMs. Not " + kem.Name())
	}

	encoder.maskEmpty = 0xff & (0xff << lastByteUsed)
	encoder.maskUsed = ^encoder.maskEmpty
	encoder.maskLast = (0x01 << (lastByteUsed - 1))
	encoder.maskRand = encoder.maskEmpty | encoder.maskLast
}
func (encoder *HqcEncoder) LengthObfuscatedCiphertext() int {
	return encoder.sizeCt
}
func (encoder *HqcEncoder) FilterPublicKey(publicKey []byte) (ok bool) {
	if encoder.forcePkParity {
		// public key is saved as pk = (seed2, s) and h must be generated from seed2
		seed2 := publicKey[:seedSize]
		hPoly := encoder.seedexpander(seed2)
		// public keys with h(1)=0 should be rejected
		return encoder.getParity(hPoly) != 0
	} else {
		return true
	}
}
func (encoder *HqcEncoder) EncodeCiphertext(obfCiphertext []byte, kemCiphertext []byte) (ok bool) {
	var rand_byte [1]byte
	err := csrand.Bytes(rand_byte[:])
	if err != nil {
		return false
	}

	copy(obfCiphertext, kemCiphertext)
	// clear bits that will be randomized
	obfCiphertext[encoder.numBytesPoly-1] &= (^encoder.maskRand)
	// replace bits to be randomized
	obfCiphertext[encoder.numBytesPoly-1] |= (encoder.maskRand & rand_byte[0])

	return true
}
func (encoder *HqcEncoder) DecodeCiphertext(kemCiphertext []byte, obfCiphertext []byte) {
	copy(kemCiphertext, obfCiphertext)
	// clear bits that were randomized
	kemCiphertext[encoder.numBytesPoly-1] &= (^encoder.maskRand)
	// reconstruct the last bit using parity of the rest
	parBit := encoder.getParity(kemCiphertext)
	if parBit != 0 {
		kemCiphertext[encoder.numBytesPoly-1] |= encoder.maskLast
	}
}

var _ filter_encode.FilterEncodeObfuscator = (*HqcEncoder)(nil)
