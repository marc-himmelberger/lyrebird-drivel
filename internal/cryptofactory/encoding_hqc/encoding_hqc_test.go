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

package encoding_hqc

import (
	"bytes"
	"flag"
	"os"
	"testing"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/cryptofactory/oqs_wrapper"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/kems"
)

var parameterSets = []string{
	"HQC-128", "HQC-192", "HQC-256",
}

const minFilterKeepRate = float32(0.5 - 0.1) // FilterPublicKey should not reject more than half
const minSuccessRate = float32(1.0)          // encoding should never reject
const minLooksOkRate = float32(0.9375 - 0.1) // 2^-4 probability of all padding bits being 0 and some margin

// Number of times to repeat correctness tests for applicable KEMs.
var numRepeats int

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		numRepeats = 100
	} else {
		numRepeats = 1000
	}
	code := m.Run()
	os.Exit(code)
}

func TestEncoding(t *testing.T) {
	for _, kemName := range parameterSets {
		t.Run(kemName, func(t *testing.T) {
			keygenOkNum := 0
			encodingOkNum := 0
			looksOkNum := 0
			for range numRepeats {
				keygenOk, encodingOk, looksOk := testSingleKemEncoding(t, kemName)
				if keygenOk {
					keygenOkNum++
					if encodingOk {
						encodingOkNum++
						if looksOk {
							looksOkNum++
						}
					}
				}
			}

			filterKeepRate := float32(keygenOkNum) / float32(numRepeats)
			successRate := float32(encodingOkNum) / float32(keygenOkNum)
			looksOkRate := float32(looksOkNum) / float32(encodingOkNum)
			if filterKeepRate < minFilterKeepRate {
				t.Fatalf("Filter-Keep Rate of %f too low. Minimum: %f", filterKeepRate, minFilterKeepRate)
			}
			t.Logf("Filter-Keep Rate of %f acceptable. Minimum: %f", filterKeepRate, minFilterKeepRate)
			if successRate < minSuccessRate {
				t.Fatalf("Success Rate of %f too low. Minimum: %f", successRate, minSuccessRate)
			}
			t.Logf("Success Rate of %f acceptable. Minimum: %f", successRate, minSuccessRate)
			if looksOkRate < minLooksOkRate {
				t.Fatalf("Looks-OK Rate of %f too low. Minimum: %f", looksOkRate, minLooksOkRate)
			}
			t.Logf("Looks-OK Rate of %f acceptable. Minimum: %f", looksOkRate, minLooksOkRate)
		})
	}
}

func testSingleKemEncoding(t *testing.T, kemName string) (keygenOk bool, encodingOk bool, looksOk bool) {
	kem := (kems.KeyEncapsulationMechanism)(oqs_wrapper.NewOqsWrapper(kemName))
	encoder := &HqcEncoder{}

	encoder.Init(kem)

	// Specific to HQC: Check KEM output size
	if kem.LengthCiphertext() != encoder.sizeCt {
		panic("Received invalid ciphertext size from KEM")
	}

	// KeyGen
	keypair := kem.KeyGen()
	keygenOk = encoder.FilterPublicKey(keypair.Public().Bytes())
	if !keygenOk {
		t.Log("encoder.FilterPublicKey(pk) failed")
		return
	}

	// Specific to HQC: Check that h-parity is 1 if forcePk is on
	seed2 := keypair.Public().Bytes()[:seedSize]
	hPoly := encoder.seedexpander(seed2)
	if encoder.forcePkParity && encoder.getParity(hPoly) == 0 {
		t.Fatalf("h(1)=0 even though forcePkParity is on")
	}

	// Encaps
	ctxt, _, _ := kem.Encaps(keypair.Public())

	// Specific to HQC: Check that top bits are 0 (excluding last used bit)
	if ctxt.Bytes()[encoder.numBytesPoly-1]&encoder.maskEmpty != 0 {
		t.Fatalf("Non-zero padding found in KEM")
	}
	// Specific to HQC: Check that u-parity is 0
	if encoder.getParity(ctxt.Bytes()) != 0 {
		t.Fatalf("u(1)=1 violating the core encoding premise")
	}

	// EncodeCtxt
	encodedCtxt := make([]byte, encoder.LengthObfuscatedCiphertext())
	encodingOk = encoder.EncodeCiphertext(encodedCtxt, ctxt.Bytes())
	if !encodingOk {
		t.Log("encoder.EncodeCiphertext(ctxt) failed")
		return
	}

	// Specific to HQC: Check that top bits are not 0 (including last used bit)
	if encodedCtxt[encoder.numBytesPoly-1]&encoder.maskRand == 0 {
		t.Log("Padding still resulted in zero bits")
		looksOk = false
	} else {
		looksOk = true
	}

	// DecodeCtxt
	decodedCtxt := make([]byte, kem.LengthCiphertext())
	encoder.DecodeCiphertext(decodedCtxt, encodedCtxt)
	if !bytes.Equal(ctxt.Bytes(), decodedCtxt) {
		t.Fatalf("correctness violation in encoding: expected %x, actual: %x", ctxt.Bytes(), decodedCtxt)
	}

	return
}

func TestParityRelation(t *testing.T) {
	for _, kemName := range parameterSets {
		t.Run(kemName, func(t *testing.T) {
			for range numRepeats {
				testParityRelation(t, kemName)
			}
		})
	}
}

func testParityRelation(t *testing.T, kemName string) {
	kem := (kems.KeyEncapsulationMechanism)(oqs_wrapper.NewOqsWrapper(kemName))
	encoder := &HqcEncoder{}

	encoder.Init(kem)

	// KeyGen
	keypair := kem.KeyGen()

	// Encaps
	ctxt, _, _ := kem.Encaps(keypair.Public())

	// Expand public key to polynomial
	seed2 := keypair.Public().Bytes()[:seedSize]
	hPoly := encoder.seedexpander(seed2)

	// Check that baseline assumption holds about parity connection between u and h,
	// namely:  u(1)=(1 + h(1)) * w_r  (mod 2)
	u1 := int(encoder.getParity(ctxt.Bytes()))
	h1 := int(encoder.getParity(hPoly))

	var wr int
	switch kem.Name() {
	case "HQC-128":
		wr = 75
	case "HQC-192":
		wr = 114
	case "HQC-256":
		wr = 149
	default:
		panic("encoding_hqc: This encoder is only applicable for HQC KEMs. Not " + kem.Name())
	}

	expectedU1 := ((1 + h1) * wr) % 2

	if u1 != expectedU1 {
		t.Fatalf("parity unexpected: u(1)=%v, but expected %v", u1, expectedU1)
	}
}
