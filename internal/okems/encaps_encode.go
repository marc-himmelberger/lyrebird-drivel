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

// The encaps_encode.go file defines the encapsulate-then-encode
// construction defined in https://eprint.iacr.org/2024/1086.

package okems // import "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/okems"

import (
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/log"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/kems"
)

// Encoders should not allocate memory nor check slice lengths.
// Encoders may panic if the slice lengths are invalid.
type EncapsThenEncode interface {
	Init(kems.KeyEncapsulationMechanism)
	LengthObfuscatedCiphertext() int
	EncodeCiphertext(obfCiphertext []byte, kemCiphertext []byte) (ok bool)
	DecodeCiphertext(kemCiphertext []byte, obfCiphertext []byte)
}

type EncapsThenEncodeOKEM struct {
	kem     kems.KeyEncapsulationMechanism
	encoder EncapsThenEncode
}

// Name of encaps-then-encapsulate construction only prefixes "EtE-"
func (ete *EncapsThenEncodeOKEM) Name() string {
	return "EtE-" + ete.kem.Name()
}

// LengthPublicKey of encaps-then-encapsulate construction uses KEM directly
func (ete *EncapsThenEncodeOKEM) LengthPublicKey() int {
	return ete.kem.LengthPublicKey()
}

// LengthPrivateKey of encaps-then-encapsulate construction uses KEM directly
func (ete *EncapsThenEncodeOKEM) LengthPrivateKey() int {
	return ete.kem.LengthPrivateKey()
}

// LengthCiphertext of encaps-then-encapsulate construction replaces the length
// of KEM ciphertexts by the length of the encoder's output
func (ete *EncapsThenEncodeOKEM) LengthCiphertext() int {
	return ete.encoder.LengthObfuscatedCiphertext()
}

// LengthSharedSecret of encaps-then-encapsulate construction uses KEM directly
func (ete *EncapsThenEncodeOKEM) LengthSharedSecret() int {
	return ete.kem.LengthSharedSecret()
}

// KeyGen of encaps-then-encapsulate construction uses KEM directly
func (ete *EncapsThenEncodeOKEM) KeyGen() *Keypair {
	kemKeypair := ete.kem.KeyGen()

	keypair := new(Keypair)
	keypair.private = PrivateKey(kemKeypair.Private())
	keypair.public = PublicKey(kemKeypair.Public())

	return keypair
}

// Encaps of encaps-then-encapsulate construction performs KEM encapsulation and
// then encodes the resulting ciphertext using the encoder, not changing the shared secret
func (ete *EncapsThenEncodeOKEM) Encaps(public PublicKey) (ObfuscatedCiphertext, SharedSecret) {
	kemPublicKey := (kems.PublicKey)(public)

	kemCiphertext, sharedSecret := ete.kem.Encaps(kemPublicKey)

	obfCiphertext := make([]byte, ete.encoder.LengthObfuscatedCiphertext())
	for {

		ok := ete.encoder.EncodeCiphertext(obfCiphertext, kemCiphertext)
		if !ok {
			log.Debugf("encaps_encode - retrying encode for ciphertext")
			continue
		}

		return ObfuscatedCiphertext(obfCiphertext), SharedSecret(sharedSecret)
	}
}

// Decaps of encaps-then-encapsulate construction uses the encoder to decode the ciphertext,
// and performs KEM decapsulation on the result
func (ete *EncapsThenEncodeOKEM) Decaps(private PrivateKey, obfCiphertext ObfuscatedCiphertext) SharedSecret {
	kemPrivateKey := (kems.PrivateKey)(private)

	kemCiphertext := make([]byte, ete.kem.LengthCiphertext())
	ete.encoder.DecodeCiphertext(kemCiphertext, obfCiphertext)

	sharedSecret := ete.kem.Decaps(kemPrivateKey, kemCiphertext)

	return SharedSecret(sharedSecret)
}

var _ ObfuscatedKem = (*EncapsThenEncodeOKEM)(nil)
