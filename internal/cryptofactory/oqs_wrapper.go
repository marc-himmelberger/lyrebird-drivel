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

// The oqs_wrapper.go file wraps the open-quantum-safe package [oqs]
// to conform to the [kems.KeyEncapsulationMechanism] interface.

package cryptofactory

import (
	"github.com/open-quantum-safe/liboqs-go/oqs"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/log"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/cryptodata"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/kems"
)

var oqsEnabledKEMs []string

func init() {
	supportedKEMs := oqs.SupportedKEMs()
	log.Infof("OQS - supported KEMs: %s", supportedKEMs)
	oqsEnabledKEMs = oqs.EnabledKEMs()
	log.Infof("OQS - enabled KEMs:   %s", oqsEnabledKEMs)
}

// Wraps an [oqs.KeyEncapsulation] to conform to [kems.KeyEncapsulationMechanism]
type OqsWrapperKEM struct {
	details oqs.KeyEncapsulationDetails
}

func (wrapper *OqsWrapperKEM) Name() string {
	return wrapper.details.Name
}
func (wrapper *OqsWrapperKEM) LengthPublicKey() int {
	return wrapper.details.LengthPublicKey
}
func (wrapper *OqsWrapperKEM) LengthPrivateKey() int {
	return wrapper.details.LengthSecretKey
}
func (wrapper *OqsWrapperKEM) LengthCiphertext() int {
	return wrapper.details.LengthCiphertext
}
func (wrapper *OqsWrapperKEM) LengthSharedSecret() int {
	return wrapper.details.LengthSharedSecret
}

func (wrapper *OqsWrapperKEM) KeyGen() *kems.Keypair {
	var kem oqs.KeyEncapsulation
	kem.Init(wrapper.details.Name, nil)
	defer kem.Clean()

	publicKey, err := kem.GenerateKeyPair()
	if err != nil {
		panic("cryptofactory: Unable to generate OQS key pair: " + err.Error())
	}

	return kems.KeypairFromBytes(
		kem.ExportSecretKey(), publicKey,
		wrapper.LengthPrivateKey(), wrapper.LengthPublicKey(),
	)
}
func (wrapper *OqsWrapperKEM) Encaps(public kems.PublicKey) (kems.Ciphertext, kems.SharedSecret, error) {
	var kem oqs.KeyEncapsulation
	kem.Init(wrapper.details.Name, nil)
	defer kem.Clean()

	public.AssertSize(wrapper.details.LengthPublicKey)

	ctxt, shared, err := kem.EncapSecret(public.Bytes())
	if err != nil {
		return kems.Ciphertext(cryptodata.Nil), kems.SharedSecret(cryptodata.Nil), err
	}

	kemCiphertext, err := cryptodata.New(ctxt, wrapper.LengthCiphertext())
	if err != nil {
		return kems.Ciphertext(cryptodata.Nil), kems.SharedSecret(cryptodata.Nil), err
	}
	sharedSecret, err := cryptodata.New(shared, wrapper.LengthSharedSecret())
	if err != nil {
		return kems.Ciphertext(cryptodata.Nil), kems.SharedSecret(cryptodata.Nil), err
	}

	return kems.Ciphertext(kemCiphertext), kems.SharedSecret(sharedSecret), nil
}
func (wrapper *OqsWrapperKEM) Decaps(private kems.PrivateKey, ciphertext kems.Ciphertext) (kems.SharedSecret, error) {
	var kem oqs.KeyEncapsulation
	kem.Init(wrapper.details.Name, private.Bytes())
	defer kem.Clean()

	ciphertext.AssertSize(wrapper.details.LengthCiphertext)
	private.AssertSize(wrapper.details.LengthSecretKey)

	shared, err := kem.DecapSecret(ciphertext.Bytes())
	if err != nil {
		return kems.SharedSecret(cryptodata.Nil), err
	}

	sharedSecret, err := cryptodata.New(shared, wrapper.LengthSharedSecret())
	if err != nil {
		return kems.SharedSecret(cryptodata.Nil), err
	}

	return kems.SharedSecret(sharedSecret), nil
}

func NewOqsWrapper(kemName string) *OqsWrapperKEM {
	var kem oqs.KeyEncapsulation
	kem.Init(kemName, nil)
	defer kem.Clean()

	return &OqsWrapperKEM{kem.Details()}
}

var _ kems.KeyEncapsulationMechanism = (*OqsWrapperKEM)(nil)
