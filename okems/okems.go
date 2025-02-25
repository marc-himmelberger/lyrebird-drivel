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

// Package okemn provides a Go wrapper and unified interface around the
// implementation of obfuscated KEMs as e.g. constructed in
// https://eprint.iacr.org/2024/1086.
// Implementation leans heavily on
// gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/ntor/ntor.go

package okems // import "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/okems"

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/open-quantum-safe/liboqs-go/oqs"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/log"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/okems/x25519ell2"
)

var kemDetails oqs.KeyEncapsulationDetails
var encoder KeygenEncapsThenEncode

// PublicKeyLengthError is the error returned when the public key being
// imported is an invalid length.
type PublicKeyLengthError int

func (e PublicKeyLengthError) Error() string {
	return fmt.Sprintf("okems: Invalid OKEM public key length for %s: %d",
		kemDetails.Name, int(e))
}

// PrivateKeyLengthError is the error returned when the private key being
// imported is an invalid length.
type PrivateKeyLengthError int

func (e PrivateKeyLengthError) Error() string {
	return fmt.Sprintf("okems: Invalid OKEM private key length for %s: %d",
		kemDetails.Name, int(e))
}

// Encoders should not allocate memory nor check slice lengths.
// Encoders may panic if the slice lengths are invalid.
type KeygenEncapsThenEncode interface {
	Init(oqs.KeyEncapsulationDetails)
	LengthPublicKey() int
	LengthCiphertext() int
	EncodePublicKey(obfPublicKey []byte, kemPublicKey []byte) (ok bool)
	DecodePublicKey(kemPublicKey []byte, obfPublicKey []byte)
	EncodeCiphertext(obfCiphertext []byte, kemCiphertext []byte) (ok bool)
	DecodeCiphertext(kemCiphertext []byte, obfCiphertext []byte)
}

func init() {
	supportedKEMs := oqs.SupportedKEMs()
	log.Infof("OQS - supported KEMs: %s", supportedKEMs)
	enabledKEMs := oqs.EnabledKEMs()
	log.Infof("OQS - enabled KEMs:   %s", enabledKEMs)

	// HACK: The proper way would be to add a TOR_PT_CLIENT_TRANSPORT_OPTIONS
	// but this would require forking goptlib which is why we add a dedicated variable instead
	kemName := os.Getenv("TOR_PT_PQOBFS_KEM")
	if kemName == "" {
		panic("no TOR_PT_PQOBFS_KEM environment variable")
	}

	if kemName == "x25519" {
		kemDetails = x25519ell2.X25519Details()
	} else {
		var kem oqs.KeyEncapsulation
		kem.Init(kemName, nil)
		kemDetails = kem.Details()
		kem.Clean()
	}

	// TODO: add other implementations from https://github.com/open-quantum-safe/liboqs/blob/main/src/kem/kem.h#L42
	switch kemDetails.Name {
	case "x25519":
		encoder = &x25519ell2.X25519ell2Encoder{}
	//case "KEM1", "KEM2":
	//	encoder = Kem1Encoder{}
	default:
		panic(fmt.Sprintf("no encoding mapped for KEM %s", kemDetails.Name))
	}
	encoder.Init(kemDetails)
}

// PublicKey is an OKEM public key in little-endian byte order.
type PublicKey struct {
	kemPublicKey []byte
	obfuscated   []byte
}

// Bytes returns a slice to the obfuscated OKEM public key.
func (public *PublicKey) Bytes() []byte {
	return public.obfuscated
}

// Hex returns the hexdecimal representation of the OKEM public key.
func (public *PublicKey) Hex() string {
	return hex.EncodeToString(public.Bytes())
}

// NewPublicKey creates a PublicKey from the raw bytes (obfuscated).
func NewPublicKey(raw []byte) (*PublicKey, error) {
	if len(raw) != encoder.LengthPublicKey() {
		return nil, PublicKeyLengthError(len(raw))
	}

	pubKey := new(PublicKey)
	copy(pubKey.obfuscated, raw)
	pubKey.kemPublicKey = make([]byte, kemDetails.LengthPublicKey)
	encoder.DecodePublicKey(pubKey.kemPublicKey, pubKey.obfuscated)

	return pubKey, nil
}

// PublicKeyFromHex returns a PublicKey from the hexdecimal representation.
func PublicKeyFromHex(encoded string) (*PublicKey, error) {
	raw, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	return NewPublicKey(raw)
}

// PrivateKey is an unobfuscated KEM private key in little-endian byte order.
type PrivateKey struct {
	kemPrivateKey []byte
}

// Bytes returns a slice to the KEM private key.
func (private *PrivateKey) Bytes() []byte {
	return private.kemPrivateKey
}

// Hex returns the hexdecimal representation of the KEM private key.
func (private *PrivateKey) Hex() string {
	return hex.EncodeToString(private.Bytes())
}

// Keypair is an OKEM keypair, consisting of obfuscated KEM public key
// and an unobfuscated KEM private key.
type Keypair struct {
	private *PrivateKey
	public  *PublicKey
}

// Public returns the OKEM public key belonging to the Keypair.
func (keypair *Keypair) Public() *PublicKey {
	return keypair.public
}

// Private returns the OKEM private key belonging to the Keypair.
func (keypair *Keypair) Private() *PrivateKey {
	return keypair.private
}

// NewKeypair generates a new OKEM keypair.
func NewKeypair() (*Keypair, error) {
	var err error
	var kem oqs.KeyEncapsulation

	keypair := new(Keypair)
	keypair.private = new(PrivateKey)
	keypair.public = new(PublicKey)

	if kemDetails.Name == "x25519" {
		err = x25519ell2.NewKeypair(keypair.private.kemPrivateKey, keypair.public.kemPublicKey, keypair.public.obfuscated)
		if err != nil {
			return nil, err
		} else {
			return keypair, nil
		}
	} else {
		// Keygen-encapsulate-then-encode construction

		for {
			// Do KeyGen of KEM
			kem.Init(kemDetails.Name, nil)
			keypair.public.kemPublicKey, err = kem.GenerateKeyPair()
			if err != nil {
				return nil, err
			}
			keypair.private.kemPrivateKey = kem.ExportSecretKey()
			kem.Clean()

			// Try Encode of pk
			keypair.public.obfuscated = make([]byte, encoder.LengthPublicKey())
			ok := encoder.EncodePublicKey(keypair.public.obfuscated, keypair.public.kemPublicKey)
			// Continue if Encode error encountered
			if !ok {
				log.Debugf("okems - retrying encode for public key")
				continue
			}

			return keypair, nil
		}
	}
}

// KeypairFromHex returns a Keypair from the hexdecimal representation of the
// the public and private key. Public keys cannot always be reconstructed
// from private keys, see https://github.com/open-quantum-safe/liboqs/issues/1802
// Inputs must correpsond to outputs of the corresponding Hex() functions
func KeypairFromHex(encodedPrivate string, encodedPublic string) (*Keypair, error) {
	rawPrivate, err := hex.DecodeString(encodedPrivate)
	if err != nil {
		return nil, err
	}

	if len(rawPrivate) != kemDetails.LengthSecretKey {
		return nil, PrivateKeyLengthError(len(rawPrivate))
	}

	keypair := new(Keypair)

	keypair.private = new(PrivateKey)
	copy(keypair.private.kemPrivateKey, rawPrivate)

	keypair.public, err = PublicKeyFromHex(encodedPublic)
	if err != nil {
		return nil, err
	}

	return keypair, nil
}

// Encaps performs OKEM encapsulation given a public key, and returns the
// corresponding ciphertext and shared secret.
func Encaps(public *PublicKey) (obfCiphertext []byte, sharedSecret []byte, err error) {
	var kem oqs.KeyEncapsulation
	var kemCiphertext []byte

	if kemDetails.Name == "x25519" {
		// ciphertext is a novel obfuscated public key
		obfCiphertext, sharedSecret, err = x25519ell2.OkemEncaps(public.kemPublicKey)
		if err != nil {
			return nil, nil, err
		} else {
			return obfCiphertext, sharedSecret, nil
		}
	} else {
		// Keygen-encapsulate-then-encode construction
		kem.Init(kemDetails.Name, nil)
		defer kem.Clean()

		for {
			// Do Encaps of KEM
			kemCiphertext, sharedSecret, err = kem.EncapSecret(public.kemPublicKey)
			if err != nil {
				return nil, nil, err
			}

			// Try Encode of ctxt
			obfCiphertext = make([]byte, encoder.LengthCiphertext())
			ok := encoder.EncodeCiphertext(obfCiphertext, kemCiphertext)
			// Continue if Encode error encountered
			if !ok {
				log.Debugf("okems - retrying encode for ciphertext")
				continue
			}

			return obfCiphertext, sharedSecret, nil
		}
	}
}

// Decaps performs OKEM decapsulation given a private key and ciphertext,
// and returns the corresponding shared secret.
func Decaps(private *PrivateKey, obfCiphertext []byte) (sharedSecret []byte, err error) {
	var kem oqs.KeyEncapsulation
	var kemCiphertext []byte

	if kemDetails.Name == "x25519" {
		// ciphertext is an obfuscated public key
		sharedSecret, err = x25519ell2.OkemDecaps(private.kemPrivateKey, obfCiphertext)
		if err != nil {
			return nil, err
		} else {
			return sharedSecret, nil
		}
	} else {
		// Keygen-encapsulate-then-encode construction
		kem.Init(kemDetails.Name, private.kemPrivateKey)
		defer kem.Clean()

		// Decode of ctxt
		kemCiphertext = make([]byte, kemDetails.LengthCiphertext)
		encoder.DecodeCiphertext(kemCiphertext, obfCiphertext)

		// Do KeyGen of KEM
		sharedSecret, err = kem.DecapSecret(kemCiphertext)
		if err != nil {
			return nil, err
		}

		return sharedSecret, nil
	}
}
