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

// Package okem provides a Go wrapper and unified interface around the
// implementation of KEMs.

package kem // import "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/kem"

import "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/cryptodata"

// A KeyEncapsulationMechanism (KEM) defines an interface for key exchange mechanisms,
// a more modern abstraction for key exchange compared to e.g. Diffie-Hellman.
// KEM public keys and ciphertext may be easily distinguishable from random bits,
// and are therefore not suitable for direct transmission in Drivel.
type KeyEncapsulationMechanism interface {
	Name() string

	LengthPublicKey() int
	LengthPrivateKey() int
	LengthCiphertext() int
	LengthSharedSecret() int

	KeyGen() *Keypair
	Encaps(PublicKey) (Ciphertext, SharedSecret)
	Decaps(PrivateKey, Ciphertext) SharedSecret
}

// PublicKey is an KEM public key
type PublicKey cryptodata.CryptoData

// PrivateKey is an KEM private key
type PrivateKey cryptodata.CryptoData

// Ciphertext is an KEM ciphertext.
// This data, without knowing the private key, is indistinguishable
// from a randomly generated ciphertext, but not from random bits.
type Ciphertext cryptodata.CryptoData

// SharedSecret is an KEM shared secret suitable for use as a symmetric key
type SharedSecret cryptodata.CryptoData

// Keypair is an KEM keypair, consisting public and private keys
type Keypair struct {
	private PrivateKey
	public  PublicKey
}

// Public returns the KEM public key belonging to the Keypair.
func (keypair *Keypair) Public() PublicKey {
	return keypair.public
}

// Private returns the KEM private key belonging to the Keypair.
func (keypair *Keypair) Private() PrivateKey {
	return keypair.private
}

// KeypairFromHex returns a Keypair from the hexdecimal representation of the
// the public and private key. Public keys cannot always be reconstructed
// from private keys, see https://github.com/open-quantum-safe/liboqs/issues/1802
// Inputs must correpsond to outputs of the corresponding Hex() functions
func KeypairFromHex(kem KeyEncapsulationMechanism, encodedPrivate string, encodedPublic string) (*Keypair, error) {
	dataPrivate, err := cryptodata.NewFromHex(encodedPrivate, kem.LengthPrivateKey())
	if err != nil {
		return nil, err
	}
	dataPublic, err := cryptodata.NewFromHex(encodedPublic, kem.LengthPublicKey())
	if err != nil {
		return nil, err
	}

	keypair := new(Keypair)
	keypair.private = PrivateKey(dataPrivate)
	keypair.public = PublicKey(dataPublic)

	return keypair, nil
}
