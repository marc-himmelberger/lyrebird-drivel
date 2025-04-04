// Copyright (c) 2025, Marc Himmelberger <marc dot himmelberger at inf dot ethz dot ch>
// All rights reserved.
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

// This file bundles constants previously defined in lyrebird/common/ntor
// together with Yawning Angel's x25519ell2 implementation in lyrebird/internal/x25519ell2
// in order to provide an encapsulate-then-encode construction as in
// https://eprint.iacr.org/2024/1086.pdf
package x25519ell2

import (
	"filippo.io/edwards25519/field"
	"gitlab.com/yawning/edwards25519-extra/elligator2"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/csrand"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/kems"
)

const (
	// RepresentativeLength is the length of an Elligator representative.
	RepresentativeLength = 32
)

// Implements x25519ell2 encoding of public keys
type Elligator2Encoder struct{}

func (encoder *Elligator2Encoder) Init(_ kems.KeyEncapsulationMechanism) {
	// nothing to initialize, we only have one fixed parameter set
}
func (encoder *Elligator2Encoder) LengthObfuscatedCiphertext() int {
	return RepresentativeLength
}

// Utility function, added for fixed-tweak test cases. Used in EncodeCiphertext.
func (encoder *Elligator2Encoder) encodeCiphertextWithTweak(obfCiphertext []byte, kemCiphertext []byte, tweak byte) (ok bool) {
	// Convert kemCiphertext back to field element u.
	// This requires u to be invariant under u.SetBytes(u.Bytes()) which is tested as [testIdempotentBytes]
	pkArr := (*[PublicKeyLength]byte)(kemCiphertext)

	var u field.Element
	if _, err := u.SetBytes(pkArr[:]); err != nil {
		// Panic is fine, the only way this fails is if the representative
		// is not 32-bytes.
		panic("internal/x25519: failed to deserialize representative: " + err.Error())
	}

	return uToRepresentative((*[32]byte)(obfCiphertext), &u, tweak)
}

// Pieced together from /lyrebird/common/ntor/ntor.go
// Takes an unobfuscated public key (not a representative), and
// gives out an obfuscated public key (as a corresponding representative)
func (encoder *Elligator2Encoder) EncodeCiphertext(obfCiphertext []byte, kemCiphertext []byte) (ok bool) {
	// Generate tweak and call internal function
	var tweak [1]byte
	if err := csrand.Bytes(tweak[:]); err != nil {
		panic("x25519ell2: Could not read enough randomness: " + err.Error())
	}

	return encoder.encodeCiphertextWithTweak(obfCiphertext, kemCiphertext, tweak[0])
}

// Pieced together from /lyrebird/common/ntor/ntor.go
// Takes an obfuscated public key (in place of obfuscated ciphertext),
// and gives out an unobfuscated public key after decoding it
func (encoder *Elligator2Encoder) DecodeCiphertext(kemCiphertext []byte, obfCiphertext []byte) {
	obfPkArr := (*[RepresentativeLength]byte)(obfCiphertext)

	// Representatives are encoded in 254 bits.
	var clamped [32]byte
	copy(clamped[:], obfPkArr[:])
	clamped[31] &= 63

	var fe field.Element
	if _, err := fe.SetBytes(clamped[:]); err != nil {
		// Panic is fine, the only way this fails is if the representative
		// is not 32-bytes.
		panic("internal/x25519ell2: failed to deserialize representative: " + err.Error())
	}
	u, _ := elligator2.MontgomeryFlavor(&fe)
	copy(kemCiphertext[:], u.Bytes())
}
