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

package cryptofactory

import (
	"bytes"
	"testing"
)

// Number of times to repeat correctness tests.
// Testing all OQS KEMs takes forever - but we could restrict those
const numRepeats = 2

// TestKemCorrectness tests correctness for all KEMs.
func TestKemCorrectness(t *testing.T) {
	kemNames := KemNames()
	t.Log("Testing KEMs:", kemNames)

	for _, kemName := range kemNames {
		t.Run(kemName, func(t *testing.T) {
			for range numRepeats {
				testSingleKemCorrectness(t, kemName)
			}
		})
	}
}

// testSingleKemCorrectness tests correctness for one run of one KEM.
func testSingleKemCorrectness(t *testing.T, kemName string) {
	kem := NewKem(kemName)

	// KeyGen
	keypair := kem.KeyGen()
	if keypair == nil {
		t.Fatal("KeyGen() returned nil")
	}

	// Encaps
	ctxt, sharedSecret1, err := kem.Encaps(keypair.Public())
	if err != nil {
		t.Fatal("kem.Encaps(pk) failed:", err)
	}

	// Decaps
	sharedSecret2, err := kem.Decaps(keypair.Private(), ctxt)
	if err != nil {
		t.Fatal("kem.Decaps(sk, c) failed:", err)
	}
	if !bytes.Equal(sharedSecret1.Bytes(), sharedSecret2.Bytes()) {
		t.Fatalf("correctness violation: expected %x, actual: %x", sharedSecret1.Bytes(), sharedSecret2.Bytes())
	}
}

// TestOkemCorrectness tests correctness for all OKEMs.
func TestOkemCorrectness(t *testing.T) {
	okemNames := OkemNames()
	t.Log("Testing OKEMs:", okemNames)

	for _, okemName := range okemNames {
		t.Run(okemName, func(t *testing.T) {
			for range numRepeats {
				testSingleOkemCorrectness(t, okemName)
			}
		})
	}
}

// testSingleOkemCorrectness tests correctness for one run of one OKEM.
func testSingleOkemCorrectness(t *testing.T, okemName string) {
	okem := NewOkem(okemName)

	// KeyGen
	keypair := okem.KeyGen()
	if keypair == nil {
		t.Fatal("KeyGen() returned nil")
	}

	// Encaps
	ctxt, sharedSecret1, err := okem.Encaps(keypair.Public())
	if err != nil {
		t.Fatal("kem.Encaps(pk) failed:", err)
	}

	// Decaps
	sharedSecret2, err := okem.Decaps(keypair.Private(), ctxt)
	if err != nil {
		t.Fatal("kem.Decaps(sk, c) failed:", err)
	}
	if !bytes.Equal(sharedSecret1.Bytes(), sharedSecret2.Bytes()) {
		t.Fatalf("correctness violation: expected %x, actual: %x", sharedSecret1.Bytes(), sharedSecret2.Bytes())
	}
}

// BenchmarkKems benchmarks KeyGen, Encaps, Decaps for all KEMs.
func BenchmarkKems(b *testing.B) {
	kemNames := KemNames()
	b.Log("Benchmarking KEMs:", kemNames)

	for _, kemName := range kemNames {
		kem := NewKem(kemName)

		b.Run(kemName+"-KeyGen", func(b *testing.B) {
			for b.Loop() {
				kem.KeyGen()
			}
		})
		b.Run(kemName+"-Encaps", func(b *testing.B) {
			kp := kem.KeyGen()
			for b.Loop() {
				kem.Encaps(kp.Public())
			}
		})
		b.Run(kemName+"-Decaps", func(b *testing.B) {
			kp := kem.KeyGen()
			c, _, _ := kem.Encaps(kp.Public())
			for b.Loop() {
				kem.Decaps(kp.Private(), c)
			}
		})
	}
}

// BenchmarkOkems benchmarks KeyGen, Encaps, Decaps for all OKEMs.
func BenchmarkOkems(b *testing.B) {
	okemNames := OkemNames()
	b.Log("Benchmarking OKEMs:", okemNames)

	for _, okemName := range okemNames {
		okem := NewOkem(okemName)

		b.Run(okemName+"-KeyGen", func(b *testing.B) {
			for b.Loop() {
				okem.KeyGen()
			}
		})
		b.Run(okemName+"-Encaps", func(b *testing.B) {
			kp := okem.KeyGen()
			for b.Loop() {
				okem.Encaps(kp.Public())
			}
		})
		b.Run(okemName+"-Decaps", func(b *testing.B) {
			kp := okem.KeyGen()
			c, _, _ := okem.Encaps(kp.Public())
			for b.Loop() {
				okem.Decaps(kp.Private(), c)
			}
		})
	}
}
