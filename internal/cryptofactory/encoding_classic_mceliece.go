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

// This file defines a simple padder that fills Classic McEliece ciphertexts top the byte boundary with random bits
package cryptofactory

import (
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/csrand"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/kems"
)

// A padder for Classic-McEliece-6960119 that adds ??? extra random bits to every ciphertext in order to make it byte-aligned
type ClassicMcEliecePadder struct{}

func (encoder *ClassicMcEliecePadder) Init(kem kems.KeyEncapsulationMechanism) {
	if kem.Name() != "Classic-McEliece-6960119" {
		panic("encoding_classic_mceliece: This encoder is only required for non-byte aligned parameter sets. This is only 6960119. " +
			kem.Name() +
			" can be used with the 'nil' encoder instead.")
	}
	if kem.LengthCiphertext() != 194 {
		panic("encoding_classic_mceliece: Received invalid ciphertext size from KEM")
	}
}
func (encoder *ClassicMcEliecePadder) LengthObfuscatedCiphertext() int {
	return 194
}
func (encoder *ClassicMcEliecePadder) EncodeCiphertext(obfCiphertext []byte, kemCiphertext []byte) (ok bool) {
	var rand_byte [1]byte
	err := csrand.Bytes(rand_byte[:])
	if err != nil {
		return false
	}

	// Mask selects empty bits
	var mask byte = 0xf8
	copy(obfCiphertext, kemCiphertext)

	if obfCiphertext[193]&mask != 0 {
		panic("encoding_classic_mceliece: Non-zero padding in KEM")
	}
	obfCiphertext[193] |= (mask & rand_byte[0])
	if obfCiphertext[193]&mask == 0 {
		panic("encoding_classic_mceliece: Padding did not work?") // TODO rm
	}
	return true
}
func (encoder *ClassicMcEliecePadder) DecodeCiphertext(kemCiphertext []byte, obfCiphertext []byte) {
	// Mask selects empty bits
	var mask byte = 0xf8
	copy(kemCiphertext, obfCiphertext)
	kemCiphertext[193] &= (^mask)
}

var _ EncapsThenEncode = (*ClassicMcEliecePadder)(nil)
