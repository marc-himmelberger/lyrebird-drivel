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
	"crypto/sha512"
	"crypto/subtle"
	"errors"

	"github.com/open-quantum-safe/liboqs-go/oqs"
	"golang.org/x/crypto/curve25519"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/csrand"
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
// where we use x25519ell2 public keys B and secret keys b,
// Encaps(B) = new keypair (Y,y), C=Y, K=B^y
// Decaps(b, Y) = Y^b
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

// TODO: Would be a much cleaner implementation if we could extract Elligator2 encoding away from
// the private key. Then x25519 could implement a KEM and we could actually use the encoding functions
// instead of panicking, and implementing an OKEM directly.
// But without a pk -> obfPk Elligator2, we need to know that we are doing OKEM while we perform KeyGen/Encaps
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

func (encoder *X25519ell2Encoder) EncodePublicKey(obfPublicKey []byte, kemPublicKey []byte) (ok bool) {
	// not used because we go from private key to public for ease (see NewKeypair below)
	panic("x25519ell2 Encoding not implemented")
}
func (encoder *X25519ell2Encoder) DecodePublicKey(kemPublicKey []byte, obfPublicKey []byte) {
	// needed for constructing PublicKey objects and Encaps()-ing on them
	pkArr := (*[PublicKeyLength]byte)(kemPublicKey)
	obfArr := (*[RepresentativeLength]byte)(obfPublicKey)
	base.RepresentativeToPublicKey(pkArr, obfArr)
}
func (encoder *X25519ell2Encoder) EncodeCiphertext(obfCiphertext []byte, kemCiphertext []byte) (ok bool) {
	// this would correspond to encoding a public key, but after using NewKeypair during OkemEncaps below,
	// this is not used because we go from private key to public for ease
	panic("x25519ell2 Encoding not implemented")
}
func (encoder *X25519ell2Encoder) DecodeCiphertext(kemCiphertext []byte, obfCiphertext []byte) {
	// identical to DecodePublicKey as ciphertext are also public keys
	encoder.DecodePublicKey(kemCiphertext, obfCiphertext)
}

// ScalarBaseMult computes a curve25519 public key from a private
// key and also computes a uniform representative for that public key.
func ScalarBaseMult(publicKey []byte, representative []byte, privateKey []byte, tweak byte) bool {
	pkArr := (*[PublicKeyLength]byte)(publicKey)
	reprArr := (*[RepresentativeLength]byte)(representative)
	privArr := (*[PrivateKeyLength]byte)(privateKey)
	return base.ScalarBaseMult(pkArr, reprArr, privArr, tweak)
}

// ### The following implement OKEM operations for x25519ell2 ###
// say the peer's KeyGen() generated B,b
// a) Encap(B) generates a new obfuscated keypair X',x and outputs c=X', K=B^x
// b) Decap(b,X') then decodes X' to X and performs X^b

// Copied from /lyrebird/common/ntor/ntor.go because this special case
// a) does not have an OQS KEM implementation
// b) uses the private key to generate obfuscated public keys (for ease)
func NewKeypair(privateBuf []byte, publicBuf []byte, obfPublicBuf []byte) error {
	var err error
	var tweak byte
	var digest [64]byte
	for {
		// Generate a Curve25519 private key.  Like everyone who does this,
		// run the CSPRNG output through SHA512 for extra tinfoil hattery.
		//
		// Also use part of the digest that gets truncated off for the
		// obfuscation tweak.
		if err = csrand.Bytes(privateBuf); err != nil {
			return err
		}
		digest = sha512.Sum512(privateBuf)
		copy(privateBuf, digest[:])

		tweak = digest[63]

		// Apply the Elligator transform.  This fails ~50% of the time.
		if !base.ScalarBaseMult((*[32]byte)(publicBuf), (*[32]byte)(obfPublicBuf), (*[32]byte)(privateBuf), tweak) {
			continue
		}

		return nil
	}
}

// Pieced together from /lyrebird/common/ntor/ntor.go
// Takes an unobfuscated public key (not a representative), and
// gives out an obfuscated public key (in place of ciphertext) plus
// a shared secret as the result of a point multiplication
func OkemEncaps(kemPublicKey []byte) ([]byte, []byte, error) {
	var privateBuf [PrivateKeyLength]byte
	var publicBuf [PublicKeyLength]byte
	var obfPublicBuf [RepresentativeLength]byte
	var sharedSecretArr [SharedSecretLength]byte

	pkArr := (*[PublicKeyLength]byte)(kemPublicKey)

	// Generate new keypair
	err := NewKeypair(privateBuf[:], publicBuf[:], obfPublicBuf[:])
	if err != nil {
		return nil, nil, err
	}

	// Client side uses EXP(Y,x) | EXP(B,x)
	curve25519.ScalarMult(&sharedSecretArr, &privateBuf, pkArr)
	notOk := constantTimeIsZero(sharedSecretArr[:])
	if notOk != 0 {
		return obfPublicBuf[:], sharedSecretArr[:], errors.New("x25519 KEM's EncapSecret failed")
	}

	return obfPublicBuf[:], sharedSecretArr[:], nil
}

// Pieced together from /lyrebird/common/ntor/ntor.go
// Takes an unobfuscated private key plus an obfuscated public key
// (in place of obfuscated ciphertext), and gives out a shared secret
// as the result of a point multiplication after decoding the received public key
func OkemDecaps(kemPrivateKey []byte, obfPublicKey []byte) (sharedSecret []byte, err error) {
	var publicBuf [PublicKeyLength]byte
	var sharedSecretArr [SharedSecretLength]byte
	var encoder X25519ell2Encoder

	obfPkArr := (*[RepresentativeLength]byte)(obfPublicKey)
	privArr := (*[PrivateKeyLength]byte)(kemPrivateKey)

	base.RepresentativeToPublicKey(&publicBuf, obfPkArr)
	encoder.DecodeCiphertext(publicBuf[:], obfPublicKey)

	// Client side uses EXP(Y,x) | EXP(B,x)
	curve25519.ScalarMult(&sharedSecretArr, privArr, &publicBuf)
	notOk := constantTimeIsZero(sharedSecretArr[:])
	if notOk != 0 {
		return sharedSecretArr[:], errors.New("x25519 KEM's DecapSecret failed")
	}

	return sharedSecretArr[:], nil
}

// Copied from /lyrebird/common/ntor/ntor.go
func constantTimeIsZero(x []byte) int {
	var ret byte
	for _, v := range x {
		ret |= v
	}

	return subtle.ConstantTimeByteEq(ret, 0)
}
