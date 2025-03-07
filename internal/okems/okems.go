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
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/cryptodata"
)

// An ObfuscatedKem (OKEM) defines an interface for key exchange mechanisms outputting
// obfuscated ciphertexts which are hard to distinguish from uniformly random bitstrings.
// Public Keys remain (as in unobfuscated KEMs) without this guarantee,
// i.e. public keys are not obfuscated.
// This is a slight departure from the definition in https://eprint.iacr.org/2024/1086
// because public key uniformity is not needed in Drivel as we only transmit encrypted
// public keys during the handshake.
// OKEM public keys are distributed with the bridge information out-of-band.
// Implementations MUST use AssertSize to check the size of arguments during Encaps, Decaps.
type ObfuscatedKem interface {
	Name() string

	LengthPublicKey() int
	LengthPrivateKey() int
	LengthCiphertext() int
	LengthSharedSecret() int

	KeyGen() *Keypair
	Encaps(PublicKey) (ObfuscatedCiphertext, SharedSecret, error)
	Decaps(PrivateKey, ObfuscatedCiphertext) (SharedSecret, error)
}

// PublicKey is an OKEM public key
type PublicKey cryptodata.CryptoData

// AssertSize checks if the public key exactly matches a given length
func (data PublicKey) AssertSize(numBytes int) error {
	return (cryptodata.CryptoData)(data).AssertSize(numBytes)
}

// Bytes returns a slice to the raw public key.
func (data PublicKey) Bytes() []byte {
	return (cryptodata.CryptoData)(data).Bytes()
}

// Hex returns the hexdecimal representation of the public key.
func (data PublicKey) Hex() string {
	return (cryptodata.CryptoData)(data).Hex()
}

// PublicKeyFromHex returns an OKEM public key from its hexdecimal representation.
// Inputs must correpsond to outputs of [PublicKey.Hex] function.
func PublicKeyFromHex(okem ObfuscatedKem, encodedPublic string) (PublicKey, error) {
	dataPublic, err := cryptodata.NewFromHex(encodedPublic, okem.LengthPublicKey())
	if err != nil {
		return PublicKey(cryptodata.Nil), err
	}

	return PublicKey(dataPublic), nil
}

// PrivateKey is an OKEM private key
type PrivateKey cryptodata.CryptoData

// AssertSize checks if the private key exactly matches a given length
func (data PrivateKey) AssertSize(numBytes int) error {
	return (cryptodata.CryptoData)(data).AssertSize(numBytes)
}

// Bytes returns a slice to the raw private key.
func (data PrivateKey) Bytes() []byte {
	return (cryptodata.CryptoData)(data).Bytes()
}

// Hex returns the hexdecimal representation of the private key.
func (data PrivateKey) Hex() string {
	return (cryptodata.CryptoData)(data).Hex()
}

// ObfuscatedCiphertext is an OKEM ciphertext.
// This data, without knowing the private key, is indistinguishable from random bits.
type ObfuscatedCiphertext cryptodata.CryptoData

// AssertSize checks if the OKEM ciphertext exactly matches a given length
func (data ObfuscatedCiphertext) AssertSize(numBytes int) error {
	return (cryptodata.CryptoData)(data).AssertSize(numBytes)
}

// Bytes returns a slice to the raw OKEM ciphertext.
func (data ObfuscatedCiphertext) Bytes() []byte {
	return (cryptodata.CryptoData)(data).Bytes()
}

// Hex returns the hexdecimal representation of the OKEM ciphertext.
func (data ObfuscatedCiphertext) Hex() string {
	return (cryptodata.CryptoData)(data).Hex()
}

// SharedSecret is an OKEM shared secret suitable for use as a symmetric key
type SharedSecret cryptodata.CryptoData

// AssertSize checks if the OKEM shared secret exactly matches a given length
func (data SharedSecret) AssertSize(numBytes int) error {
	return (cryptodata.CryptoData)(data).AssertSize(numBytes)
}

// Bytes returns a slice to the raw OKEM shared secret.
func (data SharedSecret) Bytes() []byte {
	return (cryptodata.CryptoData)(data).Bytes()
}

// Hex returns the hexdecimal representation of the OKEM shared secret.
func (data SharedSecret) Hex() string {
	return (cryptodata.CryptoData)(data).Hex()
}

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

// KeypairFromHex returns a Keypair from the raw bytes of the
// the public and private keys. Public keys cannot always be reconstructed
// from private keys, see https://github.com/open-quantum-safe/liboqs/issues/1802
// This function is intended for use within a scheme construction.
// Consumers should do serialization using the [PublicKey.Hex], [PrivateKey.Hex] methods on keys and [KeypairFromHex].
// KeypairFromBytes WILL panic if the byte slices do not exactly match the expected lengths.
func KeypairFromBytes(rawPrivate []byte, rawPublic []byte, lengthPrivate int, lengthPublic int) *Keypair {
	dataPrivate, err := cryptodata.New(rawPrivate, lengthPrivate)
	if err != nil {
		panic("okems: keypair construction with invalid private key length " + err.Error())
	}

	dataPublic, err := cryptodata.New(rawPublic, lengthPublic)
	if err != nil {
		panic("okems: keypair construction with invalid public key length " + err.Error())
	}

	keypair := new(Keypair)
	keypair.private = PrivateKey(dataPrivate)
	keypair.public = PublicKey(dataPublic)

	return keypair
}

// KeypairFromHex returns a Keypair from the hexdecimal representation of the
// the public and private keys. Public keys cannot always be reconstructed
// from private keys, see https://github.com/open-quantum-safe/liboqs/issues/1802
// Inputs must correpsond to outputs of [PublicKey.Hex], [PrivateKey.Hex].
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
