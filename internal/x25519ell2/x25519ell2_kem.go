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
// in order to provide an unobfuscated KEM
package x25519ell2

import (
	"crypto/sha512"
	"crypto/subtle"
	"errors"

	"filippo.io/edwards25519/field"
	"golang.org/x/crypto/curve25519"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/csrand"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/kems"
)

const (
	// PublicKeyLength is the length of a Curve25519 public key.
	PublicKeyLength = 32

	// PrivateKeyLength is the length of a Curve25519 private key.
	PrivateKeyLength = 32

	// SharedSecretLength is the length of a Curve25519 shared secret.
	SharedSecretLength = 32
)

// ### The following implement KEM operations for x25519 ###
// say the peer's KeyGen() generated B,b
// a) Encap(B) generates a new keypair X,x and outputs c=X, K=x.B
// b) Decap(b,X) then sets K=b.X
// This is analogous to what is done for DHKEM in [RFC 9180], but differs in the generation of shared secret:
//
// [RFC 9180] computes context = X | B
// and subsequently uses ExtractAndExpand(x.B, context) as its secret.
//
// This code uses x.B as a secret directly.
// XXX: I think this is fine, because we only use shared secrets in inputs to HMAC/HKDF, but it might be nice...
//
// [RFC 9180]: https://www.rfc-editor.org/rfc/rfc9180.html
type X25519KEM struct{}

func (kem *X25519KEM) Name() string {
	return "x25519"
}
func (kem *X25519KEM) LengthPublicKey() int {
	return PublicKeyLength
}
func (kem *X25519KEM) LengthPrivateKey() int {
	return PrivateKeyLength
}
func (kem *X25519KEM) LengthCiphertext() int {
	return PublicKeyLength
}
func (kem *X25519KEM) LengthSharedSecret() int {
	return SharedSecretLength
}

// Copied from [ntor] and substitute elligator=true, panic on errors
//
// [ntor]: https://pkg.go.dev/gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/ntor#NewKeypair
func (kem *X25519KEM) KeyGen() *kems.Keypair {
	var privateBuf [PrivateKeyLength]byte
	var publicBuf [PublicKeyLength]byte

	// Generate a Curve25519 private key.  Like everyone who does this,
	// run the CSPRNG output through SHA512 for extra tinfoil hattery.
	//
	// Also use part of the digest that gets truncated off for the
	// obfuscation tweak.
	if err := csrand.Bytes(privateBuf[:]); err != nil {
		panic("x25519: Could not read enough randomness: " + err.Error())
	}
	digest := sha512.Sum512(privateBuf[:])
	copy(privateBuf[:], digest[:])
	// XXX: Optionally make public key one byte larger, and add digest[63].
	// This would allow the encoder to yield deterministic representatitves. Do we want that?
	// Alternative: new csrand call during Encode

	// Apply the Elligator transform.  This fails ~50% of the time.
	// Inlined from ScalarBaseMult.
	u := scalarBaseMultDirty(&privateBuf)
	copy(publicBuf[:], u.Bytes())

	return kems.KeypairFromBytes(privateBuf[:], publicBuf[:], PrivateKeyLength, PublicKeyLength)
}

// Pieced together from /lyrebird/common/ntor/ntor.go
// Takes an unobfuscated public key (not a representative), and
// gives out an obfuscated public key (in place of ciphertext) plus
// a shared secret as the result of a point multiplication
func (kem *X25519KEM) Encaps(public kems.PublicKey) (kems.Ciphertext, kems.SharedSecret, error) {
	var sharedSecretArr [SharedSecretLength]byte

	public.AssertSize(PublicKeyLength)
	pkArr := (*[PublicKeyLength]byte)(public.Bytes())

	keypair := kem.KeyGen()

	// Client side uses EXP(B,x)
	curve25519.ScalarMult(&sharedSecretArr, (*[32]byte)(keypair.Private().Bytes()), pkArr)
	notOk := constantTimeIsZero(sharedSecretArr[:])
	if notOk != 0 {
		// bad server public keys can provoke this
		return nil, nil, errors.New("x25519: Encaps failure: server public keys was low-order, secret would not be secure")
	}

	return keypair.Public().Bytes(), sharedSecretArr[:], nil
}

// Pieced together from /lyrebird/common/ntor/ntor.go
// Takes a private key plus the peer's public key (in place of the ciphertext),
// and gives out a shared secret as the result of a point multiplication
func (kem *X25519KEM) Decaps(private kems.PrivateKey, ciphertext kems.Ciphertext) (kems.SharedSecret, error) {
	var publicBuf [PublicKeyLength]byte
	var sharedSecretArr [SharedSecretLength]byte

	pkArr := (*[PublicKeyLength]byte)(ciphertext.Bytes())
	privArr := (*[PrivateKeyLength]byte)(private.Bytes())

	// Ensure canonical representation before using ScalarMult
	var u field.Element
	if _, err := u.SetBytes(pkArr[:]); err != nil {
		// Panic is fine, the only way this fails is if the public key
		// is not 32-bytes.
		panic("internal/x25519: failed to deserialize public key: " + err.Error())
	}
	copy(publicBuf[:], u.Bytes())

	// Client side uses EXP(B,x)
	curve25519.ScalarMult(&sharedSecretArr, privArr, &publicBuf)
	notOk := constantTimeIsZero(sharedSecretArr[:])
	if notOk != 0 {
		// bad server public keys can provoke this
		return nil, errors.New("x25519: Encaps failure: server public keys was low-order, secret would not be secure")
	}

	return sharedSecretArr[:], nil
}

func constantTimeIsZero(x []byte) int {
	var ret byte
	for _, v := range x {
		ret |= v
	}

	return subtle.ConstantTimeByteEq(ret, 0)
}

var _ kems.KeyEncapsulationMechanism = (*X25519KEM)(nil)
