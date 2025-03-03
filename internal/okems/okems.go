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

// Package okems provides a Go wrapper and unified interface around the
// implementation of obfuscated KEMs as e.g. constructed in
// https://eprint.iacr.org/2024/1086.
// Implementation leans heavily on
// gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/ntor/ntor.go

package okems // import "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/okems"

import (
	"strings"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/cryptodata"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/kems"
)

// An ObfuscatedKem (OKEM) defines an interface for key exchange mechanisms outputting
// obfuscated ciphertexts which are hard to distinguish from uniformly random bitstrings.
// Public Keys remain (as in unobfuscated KEMs) without this guarantee,
// i.e. public keys are not obfuscated.
// This is a slight departure from the definition in https://eprint.iacr.org/2024/1086
// because public key uniformity is not needed in Drivel as we only transmit encrypted
// public keys during the handshake.
// OKEM public keys are distributed with the bridge information out-of-band.
type ObfuscatedKem interface {
	Name() string

	LengthPublicKey() int
	LengthPrivateKey() int
	LengthCiphertext() int
	LengthSharedSecret() int

	KeyGen() *Keypair
	Encaps(PublicKey) (ObfuscatedCiphertext, SharedSecret)
	Decaps(PrivateKey, ObfuscatedCiphertext) SharedSecret
}

/*
Constructs an OKEM scheme given a name.
Legal values for names are:
  - "EtE-<kem_name>" if "<kem_name>" is a valid name for
    [kems.NewKem], and a corresponding [EncapsThenEncode] is implemented.
  - TODO Optional - "OEINC[<okem1>,<okem2>]" if "<okem1>" and "<okem2>" are both
    valid names for [okems.NewOkem]
*/
func NewOkem(okemName string) *ObfuscatedKem {
	if strings.HasPrefix(okemName, "EtE-") {
		// "EtE-<kem_name>" if "<kem_name>" is a valid name for [kems.NewKem]
		// Construct KEM
		kemName := okemName[4:]
		kem := kems.NewKem(kemName)
		// Select encoder
		// TODO: cover more implementations from https://github.com/open-quantum-safe/liboqs/blob/main/src/kem/kem.h#L42
		var encoder EncapsThenEncode
		switch kemName {
		case "DHKEM":
			encoder = &x25519ell2.X25519ell2Encoder{}
		//case "KEM1", "KEM2":
		//	encoder = Kem1Encoder{}
		default:
			panic("no encoding mapped for KEM " + kemDetails.Name)
		}
		// Combine
		return NewEncapsThenEncode(kem, encoder)
	} else if strings.HasPrefix(okemName, "OEINC[") && strings.HasSuffix(okemName, "]") {
		// "OEINC[<okem1>,<okem2>]" if "<okem1>" and "<okem2>" are both valid names for [okems.NewOkem]
		// Extract names
		componentNames := okemName[6 : len(okemName)-1]
		components := strings.Split(componentNames, ",")
		if len(components) != 2 {
			panic("okem: invalid number of OEINC component OKEMs: " + okemName)
		}
		okemName1 := components[0]
		okemName2 := components[1]
		// Construct OKEMs
		okem1 := NewOkem(okemName1)
		okem2 := NewOkem(okemName2)
		// Combine
		return NewOEINC(okem1, okem2)
	} else {
		panic("okem: no OKEM construction found for name: " + okemName)
	}
}

// PublicKey is an OKEM public key
type PublicKey cryptodata.CryptoData

// PrivateKey is an OKEM private key
type PrivateKey cryptodata.CryptoData

// ObfuscatedCiphertext is an OKEM ciphertext.
// This data, without knowing the private key, is indistinguishable from random bits.
type ObfuscatedCiphertext cryptodata.CryptoData

// SharedSecret is an OKEM shared secret suitable for use as a symmetric key
type SharedSecret cryptodata.CryptoData

// Keypair is an OKEM keypair, consisting public and private keys
type Keypair struct {
	private PrivateKey
	public  PublicKey
}

// Public returns the OKEM public key belonging to the Keypair.
func (keypair *Keypair) Public() PublicKey {
	return keypair.public
}

// Private returns the OKEM private key belonging to the Keypair.
func (keypair *Keypair) Private() PrivateKey {
	return keypair.private
}

// KeypairFromHex returns a Keypair from the hexdecimal representation of the
// the public and private key. Public keys cannot always be reconstructed
// from private keys, see https://github.com/open-quantum-safe/liboqs/issues/1802
// Inputs must correpsond to outputs of the corresponding Hex() functions
func KeypairFromHex(okem ObfuscatedKem, encodedPrivate string, encodedPublic string) (*Keypair, error) {
	dataPrivate, err := cryptodata.NewFromHex(encodedPrivate, okem.LengthPrivateKey())
	if err != nil {
		return nil, err
	}
	dataPublic, err := cryptodata.NewFromHex(encodedPublic, okem.LengthPublicKey())
	if err != nil {
		return nil, err
	}

	keypair := new(Keypair)
	keypair.private = PrivateKey(dataPrivate)
	keypair.public = PublicKey(dataPublic)

	return keypair, nil
}
