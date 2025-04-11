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

package encoding_kemeleon

import (
	"bytes"
	"flag"
	"os"
	"testing"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/cryptofactory/oqs_wrapper"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/kems"
)

var parameterSets = []string{
	"ML-KEM-512",
	"ML-KEM-768",
	"ML-KEM-1024",
}

const minSuccessRate = float32(1.0)            // encoding should never reject
const minLooksOkRate = float32(0.96875 - 0.05) // 2^-5 probability of all padding bits being 0 and some margin

// Number of times to repeat correctness tests for applicable KEMs.
var numRepeats int

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		numRepeats = 10
	} else {
		numRepeats = 100
	}
	code := m.Run()
	os.Exit(code)
}

func TestEncoding(t *testing.T) {
	for _, kemName := range parameterSets {
		t.Run(kemName, func(t *testing.T) {
			encodingOkNum := 0
			looksOkNum := 0
			for range numRepeats {
				encodingOk, looksOk := testSingleKemEncoding(t, kemName)
				if encodingOk {
					encodingOkNum++
					if looksOk {
						looksOkNum++
					}
				}
			}

			successRate := float32(encodingOkNum) / float32(numRepeats)
			looksOkRate := float32(looksOkNum) / float32(encodingOkNum)
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

func testSingleKemEncoding(t *testing.T, kemName string) (ok bool, looksOk bool) {
	kem := (kems.KeyEncapsulationMechanism)(oqs_wrapper.NewOqsWrapper(kemName))
	encoder := &KemeleonEncoder{}

	encoder.Init(kem)

	// Specific to Kemeleon: Check KEM output size
	if kem.LengthCiphertext() != encoder.kemCtxtLength {
		panic("encoding_mlkem_kemeleon: Received invalid ciphertext size from KEM")
	}

	// KeyGen, Encaps
	keypair := kem.KeyGen()
	ctxt, _, _ := kem.Encaps(keypair.Public())

	// Specific to Kemeleon: Check layout of ctxt
	// TODO
	if 0 != 0 {
		t.Fatalf("KEM ciphertext looks somehow bad")
	}

	// EncodeCtxt
	encodedCtxt := make([]byte, encoder.LengthObfuscatedCiphertext())
	ok = encoder.EncodeCiphertext(encodedCtxt, ctxt.Bytes())
	if !ok {
		t.Log("encoder.EncodeCiphertext(ctxt) failed")
		return
	}

	// Specific to Kemeleon: Check layout of encodedCtxt
	// TODO
	if 0 != 0 {
		t.Log("Encoded ciphertext looks somehow bad")
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
