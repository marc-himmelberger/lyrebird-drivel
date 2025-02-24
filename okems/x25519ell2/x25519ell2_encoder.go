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

// Package x25519ell2 bundles constants previously defined in lyrebird/common/ntor
// together with Yawning Angel's x25519ell2 implementation in lyrebird/internal/x25519ell2
// in order to provide a keygen-encapsulate-then-encode obfuscated KEM as in
// https://eprint.iacr.org/2024/1086.pdf
package x25519ell2

import (
	"github.com/open-quantum-safe/liboqs-go/oqs"

	base "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/x25519ell2"
)

const (
	// PublicKeyLength is the length of a Curve25519 public key.
	PublicKeyLength = 32

	// RepresentativeLength is the length of an Elligator representative.
	RepresentativeLength = 32

	// PrivateKeyLength is the length of a Curve25519 private key.
	PrivateKeyLength = 32

	// SharedSecretLength is the length of a Curve25519 shared secret.
	SharedSecretLength = 32
)

// Functionally a constant describing the underlying KEM
func X25519Details() oqs.KeyEncapsulationDetails {
	return oqs.KeyEncapsulationDetails{
		Name:               "x25519",
		Version:            "1",
		ClaimedNISTLevel:   0,
		IsINDCCA:           true,
		LengthPublicKey:    PublicKeyLength,
		LengthSecretKey:    PrivateKeyLength,
		LengthCiphertext:   PublicKeyLength,
		LengthSharedSecret: SharedSecretLength,
	}
}

type X25519ell2Encoder struct{}

func (encoder *X25519ell2Encoder) Init(kemDetails oqs.KeyEncapsulationDetails) {
	// ignore kemDetails, as only one parameter set exists here
	return
}

func (encoder *X25519ell2Encoder) LengthPublicKey() int {
	return RepresentativeLength
}

func (encoder *X25519ell2Encoder) LengthCiphertext() int {
	return RepresentativeLength
}

func (encoder *X25519ell2Encoder) EncodePublicKey(kemPublicKey []byte) ([]byte, error) {
	// not used because we go from private key to public for ease
	panic("x25519ell2 Encoding not implemented")
}
func (encoder *X25519ell2Encoder) DecodePublicKey(obfuscated []byte) []byte {
	kemPublicKey := make([]byte, PublicKeyLength)
	pkArr := (*[PublicKeyLength]byte)(kemPublicKey)
	obfArr := (*[RepresentativeLength]byte)(obfuscated)
	base.RepresentativeToPublicKey(pkArr, obfArr)
	return kemPublicKey
}
func (encoder *X25519ell2Encoder) EncodeCiphertext(kemCiphertext []byte) ([]byte, error) {
	// TODO: where is this needed anyway?
	panic("x25519ell2 EncodingCtxt not implemented")
}
func (encoder *X25519ell2Encoder) DecodeCiphertext(obfCiphertext []byte) []byte {
	// TODO: where is this needed anyway?
	panic("x25519ell2 DecodingCtxt not implemented")
}

// ScalarBaseMult computes a curve25519 public key from a private
// key and also computes a uniform representative for that public key.
func ScalarBaseMult(publicKey []byte, representative []byte, privateKey []byte, tweak byte) bool {
	pkArr := (*[PublicKeyLength]byte)(publicKey)
	reprArr := (*[RepresentativeLength]byte)(representative)
	privArr := (*[PrivateKeyLength]byte)(privateKey)
	return base.ScalarBaseMult(pkArr, reprArr, privArr, tweak)
}
