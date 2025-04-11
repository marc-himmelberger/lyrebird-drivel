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

package encoding_kemeleon

import (
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/cryptofactory/encaps_encode"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/kems"
)

// An implementation of the ML-KEM obfuscator "Kemeleon" (Non-Rejection Sampling Variant).
// In order to use ML-KEM as an OKEM, this encoding is required for all parameter sets.
// See also https://eprint.iacr.org/2024/1086.pdf and https://datatracker.ietf.org/doc/draft-irtf-cfrg-kemeleon/
// The implementation uses inspiration from https://github.com/jmwample/kemeleon and https://github.com/rozbb/ct-kemeleon
type KemeleonEncoder struct {
	// Parameters with defaults or set in Init
	t int
	q int `default:"3329"`
	n int `default:"256"`

	kemCtxtLength      int // Length in bytes of KEM ciphertexts
	kemeleonCtxtLength int // Length in bytes of Kemeleon outputs

	// Parameters from FIPS203
	k  int
	du int
	dv int
}

// Verifies KEM and sets the parameter "t" according to the targeted security level
func (encoder *KemeleonEncoder) Init(kem kems.KeyEncapsulationMechanism) {
	// Verify KEM and set parameters
	switch kem.Name() {
	case "ML-KEM-512":
		encoder.t = 128
		encoder.kemCtxtLength = 768
		encoder.kemeleonCtxtLength = 1140
	case "ML-KEM-768":
		encoder.t = 192
		encoder.kemCtxtLength = 1088
		encoder.kemeleonCtxtLength = 1514
	case "ML-KEM-1024":
		encoder.t = 256
		encoder.kemCtxtLength = 1568
		encoder.kemeleonCtxtLength = 1889 // XXX: Are these Kemeleon numbers up-to-date with NR,I-D?
	default:
		panic("encoding_mlkem_kemeleon: This encoder is only valid for 'ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024'. Not " + kem.Name())
	}
}
func (encoder *KemeleonEncoder) LengthObfuscatedCiphertext() int {
	return encoder.kemeleonCtxtLength
}

// Corresponds to EncodeCtxt in the Internet Draft
func (encoder *KemeleonEncoder) EncodeCiphertext(obfCiphertext []byte, kemCiphertext []byte) (ok bool) {
	// TODO Consult https://github.com/C2SP/CCTV/blob/main/ML-KEM/intermediate/ML-KEM-1024.txt for debugging

	// TODO implement
}

// Corresponds to DecodeCtxt in the Internet Draft
func (encoder *KemeleonEncoder) DecodeCiphertext(kemCiphertext []byte, obfCiphertext []byte) {
	// TODO implement
}

var _ encaps_encode.EncapsThenEncode = (*KemeleonEncoder)(nil)
