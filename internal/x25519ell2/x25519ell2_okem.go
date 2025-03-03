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
// in order to provide an encapsulate-then-encode obfuscated (O)KEM as in
// https://eprint.iacr.org/2024/1086.pdf
package x25519ell2

import (
	"crypto/sha512"
	"crypto/subtle"
	"errors"

	"filippo.io/edwards25519/field"
	"gitlab.com/yawning/edwards25519-extra/elligator2"
	"golang.org/x/crypto/curve25519"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/csrand"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/okems"
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

// ### The following implement OKEM operations for x25519ell2 ###
// say the peer's KeyGen() generated B,b
// a) Encap(B) generates a new obfuscated keypair X',x and outputs c=X', K=x.B
// b) Decap(b,X') then decodes X' to X and performs b.X
// This is analogous to what is done for DHKEM in [RFC 9180], but differs in the generation of shared secret:
//
// [RFC 9180] computes context = X' | B
// and subsequently uses ExtractAndExpand(x.B, context) as its secret.
//
// This code uses x.B as a secret directly.
// XXX: I think this is fine, because we only use shared secrets in inputs to HMAC/HKDF, but it might be nice...
//
// [RFC 9180]: https://www.rfc-editor.org/rfc/rfc9180.html
type X25519ell2Okem struct{}

func (okem *X25519ell2Okem) Name() string {
	return "EtE-x25519"
}
func (okem *X25519ell2Okem) LengthPublicKey() int {
	return PublicKeyLength
}
func (okem *X25519ell2Okem) LengthPrivateKey() int {
	return PrivateKeyLength
}
func (okem *X25519ell2Okem) LengthCiphertext() int {
	return RepresentativeLength
}
func (okem *X25519ell2Okem) LengthSharedSecret() int {
	return SharedSecretLength
}

// Copied from [ntor] and substitute elligator=true, panic on errors
//
// [ntor]: https://pkg.go.dev/gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/ntor#NewKeypair
func (okem *X25519ell2Okem) KeyGen() *okems.Keypair {
	var privateBuf [PrivateKeyLength]byte
	var publicBuf [PublicKeyLength]byte
	var obfPublicBuf [RepresentativeLength]byte

	// Generate a Curve25519 private key.  Like everyone who does this,
	// run the CSPRNG output through SHA512 for extra tinfoil hattery.
	//
	// Also use part of the digest that gets truncated off for the
	// obfuscation tweak.
	//
	// Representative is not needed (no need for obfuscated public keys when not used as ciphertext)
	for {

		if err := csrand.Bytes(privateBuf[:]); err != nil {
			panic("x25519ell2: Could not read enough randomness: " + err.Error())
		}
		digest := sha512.Sum512(privateBuf[:])
		copy(privateBuf[:], digest[:])

		tweak := digest[63]

		// Apply the Elligator transform.  This fails ~50% of the time.
		// Inlined from ScalarBaseMult.
		u := scalarBaseMultDirty(&privateBuf)
		if !uToRepresentative(&obfPublicBuf, u, tweak) {
			// No representative.
			continue
		}
		copy(publicBuf[:], u.Bytes())

		keypair, err := okems.KeypairFromBytes(privateBuf[:], publicBuf[:], PrivateKeyLength, PublicKeyLength)
		if err != nil {
			panic("x25519ell2: Could not construct keypair from bytes: " + err.Error())
		}

		return keypair
	}
}

// Pieced together from /lyrebird/common/ntor/ntor.go
// Takes an unobfuscated public key (not a representative), and
// gives out an obfuscated public key (in place of ciphertext) plus
// a shared secret as the result of a point multiplication
func (okem *X25519ell2Okem) Encaps(public okems.PublicKey) (okems.ObfuscatedCiphertext, okems.SharedSecret, error) {
	var privateBuf [PrivateKeyLength]byte
	var publicBuf [PublicKeyLength]byte
	var obfPublicBuf [RepresentativeLength]byte
	var sharedSecretArr [SharedSecretLength]byte

	public.AssertSize(PublicKeyLength)
	pkArr := (*[PublicKeyLength]byte)(public.Bytes())

	// Generate new keypair:
	// Generate a Curve25519 private key.  Like everyone who does this,
	// run the CSPRNG output through SHA512 for extra tinfoil hattery.
	//
	// Also use part of the digest that gets truncated off for the
	// obfuscation tweak.
	//
	// Representative is needed (as opposed to KeyGen)
	for {

		if err := csrand.Bytes(privateBuf[:]); err != nil {
			panic("x25519ell2: Could not read enough randomness: " + err.Error())
		}
		digest := sha512.Sum512(privateBuf[:])
		copy(privateBuf[:], digest[:])

		tweak := digest[63]

		// Apply the Elligator transform.  This fails ~50% of the time.
		// Inlined from ScalarBaseMult.
		u := scalarBaseMultDirty(&privateBuf)
		if !uToRepresentative(&obfPublicBuf, u, tweak) {
			// No representative.
			continue
		}
		copy(publicBuf[:], u.Bytes())

		break
	}

	// Client side uses EXP(B,x)
	curve25519.ScalarMult(&sharedSecretArr, &privateBuf, pkArr)
	notOk := constantTimeIsZero(sharedSecretArr[:])
	if notOk != 0 {
		// bad server public keys can provoke this
		return nil, nil, errors.New("x25519ell2: Encaps failure: server public keys was low-order, secret would not be secure")
	}

	return obfPublicBuf[:], sharedSecretArr[:], nil
}

// Pieced together from /lyrebird/common/ntor/ntor.go
// Takes an unobfuscated private key plus an obfuscated public key
// (in place of obfuscated ciphertext), and gives out a shared secret
// as the result of a point multiplication after decoding the received public key
func (okem *X25519ell2Okem) Decaps(private okems.PrivateKey, obfCiphertext okems.ObfuscatedCiphertext) (okems.SharedSecret, error) {
	var publicBuf [PublicKeyLength]byte
	var sharedSecretArr [SharedSecretLength]byte

	obfPkArr := (*[RepresentativeLength]byte)(obfCiphertext.Bytes())
	privArr := (*[PrivateKeyLength]byte)(private.Bytes())

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
	copy(publicBuf[:], u.Bytes())

	// Client side uses EXP(B,x)
	curve25519.ScalarMult(&sharedSecretArr, privArr, &publicBuf)
	notOk := constantTimeIsZero(sharedSecretArr[:])
	if notOk != 0 {
		// bad server public keys can provoke this
		return nil, errors.New("x25519ell2: Encaps failure: server public keys was low-order, secret would not be secure")
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

var _ okems.ObfuscatedKem = (*X25519ell2Okem)(nil)
