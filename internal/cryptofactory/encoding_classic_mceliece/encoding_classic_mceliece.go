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

package encoding_classic_mceliece

import (
	"strings"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/csrand"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/cryptofactory/encaps_encode"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/kems"
)

// Mask selects 5 empty bits
const mask byte = 0xf8

// A padder for Classic-McEliece-6960119 that adds 5 extra random bits to every ciphertext in order to make it byte-aligned.
// All other parameter sets for Classic McEliece are already byte-aligned.
type ClassicMcEliecePadder struct{}

func (encoder *ClassicMcEliecePadder) Init(kem kems.KeyEncapsulationMechanism) {
	if kem.Name() != "Classic-McEliece-6960119" {
		if strings.HasPrefix(kem.Name(), "Classic-McEliece") {
			panic("encoding_classic_mceliece: This encoder is only required for non-byte aligned parameter sets. This is only 6960119. " +
				kem.Name() +
				" can be used with the 'nil' encoder instead.")
		} else {
			panic("encoding_classic_mceliece: This encoder is only required for Classic McEliece KEMs. Not " + kem.Name())
		}
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

	copy(obfCiphertext, kemCiphertext)
	obfCiphertext[193] |= (mask & rand_byte[0])

	return true
}
func (encoder *ClassicMcEliecePadder) DecodeCiphertext(kemCiphertext []byte, obfCiphertext []byte) {
	copy(kemCiphertext, obfCiphertext)
	kemCiphertext[193] &= (^mask)
}

var _ encaps_encode.EncapsThenEncode = (*ClassicMcEliecePadder)(nil)
