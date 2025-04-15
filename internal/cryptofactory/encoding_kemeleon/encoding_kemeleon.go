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
	"crypto/rand"
	"fmt"
	"math"
	"math/big"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/csrand"
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
		encoder.kemeleonCtxtLength = 1514 + 8 // XXX: unclear in I-D: if t corresponds to NIST, then sizes are bigger (draft uses t=128 always in Table 2)
		encoder.k = 3
		encoder.eta1 = 2
		encoder.du = 10
		encoder.dv = 4
	case "ML-KEM-1024":
		encoder.t = 256
		encoder.kemCtxtLength = 1568
		encoder.kemeleonCtxtLength = 1905 // XXX: similar
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

// Concatenates two values c1, c2 into a ciphertext
func (encoder *KemeleonEncoder) combineCtxt(c1 []byte, c2 []byte) (ctxt []byte) {
	// trivial, but this way the interface is symmetric
	return append(c1, c2...)
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

// Executes ByteEncode from FIPS203 twice to convert both parts of the ciphertext
func (encoder *KemeleonEncoder) encodeBytes(compressedU []uint16, compressedV []uint16) (c1 []byte, c2 []byte) {
	// We execute ByteEncode: k times on compressedU (du-bit integers),
	// and then once on compressedV (dv-bit integers).
	// Each call to ByteEncode consumes n integers and produces block_size bytes for d=du
	block_size := 32 * encoder.du
	c1 = make([]byte, 0, block_size*(encoder.k+1)) // extra space avoids copy for append (dv < du)
	for i := range encoder.k {
		encBlock := encoder.byteEncodeSingle(encoder.du, [256]uint16(compressedU[i*256:(i+1)*256]))
		c1 = append(c1, encBlock...)
	}
	c2 = encoder.byteEncodeSingle(encoder.dv, [256]uint16(compressedV))
	return
}

// Calculates (y * q) / 2^d (arithmetic as rationals) and rounds to the nearest integer
func decompressSingle(y uint16, d int) uint16 {
	dividend := uint32(y) * uint32(q)
	quotient := dividend >> d
	// round up  if the last dropped bit was 1
	quotient += dividend >> (d - 1) & 1
	return uint16(quotient)
}

// Calculates (x * 2^d) / q (arithmetic as rationals) and rounds to the nearest integer, then mod 2^d
// Tested against crypto/internal/fips140/mlkem/field.go
func compressSingle(x uint16, d int) uint16 {
	// If we add q/2 bevore dividing, rounding to nearest will work correctly
	dividend := uint32(x)*(1<<d) + uint32(q)/2
	return uint16(dividend/uint32(q)) % (1 << d)
}

// Executes Decompress from FIPS203 repeatedly to convert both parts of the ciphertext.
func (encoder *KemeleonEncoder) decompress(compressedU []uint16, compressedV []uint16) (u []uint16, v []uint16) {
	// We execute Decompress: k times on compressedU to get k*n integers mod q,
	// and then once on compressedV to get n integers mod q.
	u = make([]uint16, n*encoder.k, n*(encoder.k+1)) // extra space avoids copy for append
	v = make([]uint16, n)

	// Runs for k times as many iterations, but the operation is element-wise
	for i, val := range compressedU {
		u[i] = decompressSingle(val, encoder.du)
	}
	for i, val := range compressedV {
		v[i] = decompressSingle(val, encoder.dv)
	}

	return
}

// Executes Compress from FIPS203 repeatedly to convert both parts of the ciphertext.
func (encoder *KemeleonEncoder) compress(u []uint16, v []uint16) (compressedU []uint16, compressedV []uint16) {
	// We execute Compress: k times on u to get k*n integers mod 2^du,
	// and then once on v to get n integers mod 2^dv.
	compressedU = make([]uint16, n*encoder.k)
	compressedV = make([]uint16, n)

	// Runs for k times as many iterations, but the operation is element-wise
	for i, val := range u {
		compressedU[i] = compressSingle(val, encoder.du)
	}
	for i, val := range v {
		compressedV[i] = compressSingle(val, encoder.dv)
	}

	return
}

// Executes SamplePreimage from the Internet Draft once.
// Given d and a pair of decompressed and compressed values,
// this returns a suitable preimage in Z_q to avoid rejections later.
func samplePreimage(d int, u, c uint16) uint16 {
	// range for the sampling of rand, inclusive
	var rand_min, rand_max int
	switch d {
	case 10:
		if compressSingle(u+2, d) == c {
			rand_min, rand_max = -1, 2
		} else {
			rand_min, rand_max = -1, 1
		}
	case 11:
		if compressSingle(u+1, d) == c {
			rand_min, rand_max = 0, 1
		} else if compressSingle(u-1, d) == c {
			rand_min, rand_max = -1, 0
		} else {
			rand_min, rand_max = 0, 0
		}
	case 5:
		if c == 0 {
			rand_min, rand_max = -52, 52
		} else {
			rand_min, rand_max = -51, 52
		}
	case 4:
		if c == 0 {
			rand_min, rand_max = -104, 104
		} else {
			rand_min, rand_max = -104, 103
		}
	default:
		panic(fmt.Sprintf("encoding_kemeleon: Unsupported value d=%d", d))
	}
	rand := csrand.IntRange(rand_min, rand_max)
	if rand < 0 {
		rand = int(q) - rand
	}
	return (u + uint16(rand)) % q
}

// Executes VectorEncodeNR from the Internet Draft once.
// Given a vector of (k+1)*n elements of Z_q, accumulates into a large integer.
func (encoder *KemeleonEncoder) vectorEncodeNR(w []uint16) *big.Int {
	r := big.NewInt(0)
	qBig := big.NewInt(int64(q))
	z := big.NewInt(0)
	v := big.NewInt(0)

	l := len(w)                                             // (k+1)*n
	b := int(math.Ceil(float64(l) * math.Log2(float64(q)))) // log2(q^l) = l * log2(q)
	// XXX should be ceil(l*log2(q)) in draft?
	for i, val := range w {
		z.SetInt64(int64(i))   //
		z.Exp(qBig, z, nil)    // z = q^i
		v.SetInt64(int64(val)) //
		z.Mul(v, z)            // z = val * q^i
		r.Add(r, z)            // r += val * q^i
	}

	z.SetInt64(int64(b + encoder.t)) // z = b+t
	v.SetInt64(2)                    //
	v.Exp(v, z, nil)                 // v = 2^(b+t)
	v.Sub(v, r)                      // v = 2^(b+t)-r
	z.SetInt64(int64(l))             // z = (k+1)*n
	qBig.Exp(qBig, z, nil)           // qBig = q^((k+1)*n)
	v.Div(v, qBig)                   // v = floor((2^(b+t)-r)/(q^((k+1)*n)))
	v.Add(v, z.SetInt64(1))          // v++

	m, err := rand.Int(csrand.Rand, v) // m <--$ [0, v)
	if err != nil {
		panic(fmt.Sprintf("encoding_kemeleon: Unable to sample random Int: %s", err.Error()))
	}

	z.Mul(m, qBig) // z = m*q^((k+1)*n))
	r.Add(r, z)    // r += m*q^((k+1)*n))

	return r
}

// Executes VectorDecodeNR from the Internet Draft once.
// Given a large integer, returns a vector of (k+1)*n elements of Z_q.
func (encoder *KemeleonEncoder) vectorDecodeNR(r *big.Int) []uint16 {
	l := n * (encoder.k + 1)
	w := make([]uint16, l)

	qBig := big.NewInt(int64(q))
	z := big.NewInt(int64(l))
	//v := big.NewInt(0)
	z.Exp(qBig, z, nil) // z = q^((k+1)*n))
	r.Mod(r, z)         // r = r % q^((k+1)*n))
	// XXX typo in I-D, should be r instead of a
	for i := range w {
		z.Mod(r, qBig) // z = r % q
		w[i] = uint16(z.Int64())
		r.Div(r, qBig) // r = r // q
	}
	return w
}

// Corresponds to Kemeleon.EncodeCtxtNR in the Internet Draft
func (encoder *KemeleonEncoder) EncodeCiphertext(obfCiphertext []byte, kemCiphertext []byte) (ok bool) {
	// TODO Consult https://github.com/C2SP/CCTV/blob/main/ML-KEM/intermediate/ML-KEM-1024.txt for debugging

	c1, c2 := encoder.splitCtxt(kemCiphertext)
	comprU, comprV := encoder.decodeBytes(c1, c2)
	u, v := encoder.decompress(comprU, comprV)

	// Sample preimages, range for u runs for k times as many iterations,
	// but the operation is element-wise
	for i, val := range u {
		u[i] = samplePreimage(encoder.du, val, comprU[i])
	}
	for i, val := range v {
		v[i] = samplePreimage(encoder.dv, val, comprV[i])
	}

	// Concatenate vector and encode
	w := append(u, v...)
	r := encoder.vectorEncodeNR(w)

	// Serialize big.Int to obfCiphertext
	r.FillBytes(obfCiphertext)

	return true
}

// Corresponds to Kemeleon.DecodeCtxtNR in the Internet Draft
func (encoder *KemeleonEncoder) DecodeCiphertext(kemCiphertext []byte, obfCiphertext []byte) {
	// Deserialize big.Int from obfCiphertext
	r := big.NewInt(0)
	r.SetBytes(obfCiphertext)

	// Decode and split vector
	w := encoder.vectorDecodeNR(r)
	u, v := w[:n*encoder.k], w[n*encoder.k:n*(encoder.k+1)]

	// Compress
	comprU, comprV := encoder.compress(u, v)
	c1, c2 := encoder.encodeBytes(comprU, comprV)
	ctxt := encoder.combineCtxt(c1, c2)

	// Save result
	copy(kemCiphertext, ctxt)
}

var _ encaps_encode.EncapsThenEncode = (*KemeleonEncoder)(nil)
