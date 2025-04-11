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

const (
	q    uint16 = 3329
	n    int    = 256
	eta2 int    = 2
)

// An implementation of the ML-KEM obfuscator "Kemeleon" (Non-Rejection Sampling Variant).
// In order to use ML-KEM as an OKEM, this encoding is required for all parameter sets.
// See also https://eprint.iacr.org/2024/1086.pdf and https://datatracker.ietf.org/doc/draft-irtf-cfrg-kemeleon/
// The implementation uses inspiration from https://github.com/jmwample/kemeleon and https://github.com/rozbb/ct-kemeleon
type KemeleonEncoder struct {
	// Parameters with defaults or set in Init according to parameter set
	t int

	kemCtxtLength      int // Length in bytes of KEM ciphertexts, used for tests
	kemeleonCtxtLength int // Length in bytes of Kemeleon outputs

	// Parameters from FIPS203
	k    int
	eta1 int
	du   int
	dv   int
}

// Verifies KEM and sets the parameter "t" according to the targeted security level
func (encoder *KemeleonEncoder) Init(kem kems.KeyEncapsulationMechanism) {
	// Verify KEM and set parameters (values of t based on FIPS203, Table 2)
	switch kem.Name() {
	case "ML-KEM-512":
		encoder.t = 128
		encoder.kemCtxtLength = 768
		encoder.kemeleonCtxtLength = 1140
		encoder.k = 2
		encoder.eta1 = 3
		encoder.du = 10
		encoder.dv = 4
	case "ML-KEM-768":
		encoder.t = 192
		encoder.kemCtxtLength = 1088
		encoder.kemeleonCtxtLength = 1514
		encoder.k = 3
		encoder.eta1 = 2
		encoder.du = 10
		encoder.dv = 4
	case "ML-KEM-1024":
		encoder.t = 256
		encoder.kemCtxtLength = 1568
		encoder.kemeleonCtxtLength = 1889 // XXX: Are these Kemeleon numbers up-to-date with NR,I-D?
		encoder.k = 4
		encoder.eta1 = 2
		encoder.du = 11
		encoder.dv = 5
	default:
		panic("encoding_mlkem_kemeleon: This encoder is only valid for 'ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024'. Not " + kem.Name())
	}
}
func (encoder *KemeleonEncoder) LengthObfuscatedCiphertext() int {
	return encoder.kemeleonCtxtLength
}

// Parses a ciphertext as a concatenation of two values: c1 || c2
func (encoder *KemeleonEncoder) splitCtxt(ctxt []byte) (c1 []byte, c2 []byte) {
	// c1 = ByteEncode_du(Compress_du(u))
	// c2 = ByteEncode_dv(Compress_dv(v))

	// ByteEncode turns one or more d-bit integers into a byte string.
	// Compress converts field elements from Z_q to d-bit integers.
	// The resulting byte array is 32*d bytes long for each integer.
	// c1 contains k integers, while c2 contains only one.
	length_c1 := encoder.du * 32 * encoder.k
	length_c2 := encoder.dv * 32

	return ctxt[:length_c1], ctxt[length_c1 : length_c1+length_c2]
}

// Executes ByteDecode from FIPS203 once on a d*32-byte string to get n d-bit integers
func (encoder *KemeleonEncoder) byteDecodeSingle(d int, encoded []byte) (integers [n]uint16) {
	// Take d bits at a time, convert to int, add to array.
	// These d-bit blocks may go across byte boundaries.

	// start of the next d-bit block, measured in bits from the start of encoded
	var bitOffset int = 0

	for i := range n {
		var value uint16 = 0
		for bit := 0; bit < d; bit++ {
			// Look for each bit separately
			byteIndex := (bitOffset + bit) / 8
			bitIndex := (bitOffset + bit) % 8
			bitValue := (encoded[byteIndex] >> bitIndex) & 1
			value |= uint16(bitValue) << bit
		}
		integers[i] = value
		bitOffset += d
	}
	return
}

// Executes ByteEncode from FIPS203 once on a slice of n d-bit integers to  get a d*32-byte string
func (encoder *KemeleonEncoder) byteEncodeSingle(d int, integers [n]uint16) (encoded []byte) {
	// Take an integer, convert to d bits, add to buffer.
	// These d-bit blocks may go across byte boundaries.
	encoded = make([]byte, d*32)

	// start of the next d-bit block, measured in bits from the start of encoded
	var bitOffset int = 0

	for i := 0; i < n; i++ {
		value := integers[i]
		for bit := 0; bit < d; bit++ {
			byteIndex := (bitOffset + bit) / 8
			bitIndex := (bitOffset + bit) % 8
			bitValue := (value >> bit) & 1
			encoded[byteIndex] |= byte(bitValue << bitIndex)
		}
		bitOffset += d
	}
	return
}

// Executes ByteDecode from FIPS203 twice to convert both parts of the ciphertext
func (encoder *KemeleonEncoder) decodeBytes(c1 []byte, c2 []byte) (compressedU []uint16, compressedV []uint16) {
	// We execute ByteDecode: k times on c1 to get du-bit integers,
	// and then once on c2 to get dv-bit integers.
	// Each call to ByteDecode consumes block_size bytes for d=du
	block_size := 32 * encoder.du
	compressedU = make([]uint16, 0, n*encoder.k)
	for i := range encoder.k {
		intArr := encoder.byteDecodeSingle(encoder.du, c1[i*block_size:(i+1)*block_size])
		compressedU = append(compressedU, intArr[:]...)
	}
	intArr := encoder.byteDecodeSingle(encoder.dv, c2)
	compressedV = intArr[:]
	return
}

// Executes Decompress from FIPS203 repeatedly to convert both parts of the ciphertext.
// This function mutates its arguments.
func (encoder *KemeleonEncoder) decompress(compressedU []uint16, compressedV []uint16) {
	// We execute Decompress: k times on compressedU to get k*n integers mod q,
	// and then once on c2 to get n integers mod q.
	// Each call to Decompress consumes n integers

	// Calculates (y * q) / 2^d (no modular inverse!) and rounds to the neares integer
	decompressU := func(y uint16) uint16 {
		dividend := uint32(y) * uint32(q)
		quotient := dividend >> encoder.du
		// round up  if the last dropped bit was 1
		quotient += dividend >> (encoder.du - 1) & 1
		return uint16(quotient)
	}
	decompressV := func(y uint16) uint16 {
		dividend := uint32(y) * uint32(q)
		quotient := dividend >> encoder.dv
		// round up  if the last dropped bit was 1
		quotient += dividend >> (encoder.dv - 1) & 1
		return uint16(quotient)
	}

	// Runs for k times as many iterations, but the operation is element-wise
	for i, val := range compressedU {
		compressedU[i] = decompressU(val)
	}
	for i, val := range compressedV {
		compressedV[i] = decompressV(val)
	}
}

// Corresponds to EncodeCtxt in the Internet Draft
func (encoder *KemeleonEncoder) EncodeCiphertext(obfCiphertext []byte, kemCiphertext []byte) (ok bool) {
	// TODO Consult https://github.com/C2SP/CCTV/blob/main/ML-KEM/intermediate/ML-KEM-1024.txt for debugging

	copy(obfCiphertext, kemCiphertext)

	// TODO implement
	return true
}

// Corresponds to DecodeCtxt in the Internet Draft
func (encoder *KemeleonEncoder) DecodeCiphertext(kemCiphertext []byte, obfCiphertext []byte) {
	// TODO implement
	copy(kemCiphertext, obfCiphertext)
}

var _ encaps_encode.EncapsThenEncode = (*KemeleonEncoder)(nil)
