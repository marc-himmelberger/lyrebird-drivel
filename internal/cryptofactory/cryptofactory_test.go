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

import "testing"

// TestKemCorrectness tests keypair generation for all KEMs.
func TestKemCorrectness(t *testing.T) {
	// Test KEMs
	for kem in list_of_all_KEMs {
		// KeyGen
		keypair, err := NewKeypair(false)
		if err != nil {
			t.Fatal("NewKeypair(false) failed:", err)
		}
		if keypair == nil {
			t.Fatal("NewKeypair(false) returned nil")
		}
		if keypair.HasElligator() {
			t.Fatal("NewKeypair(false) has a Elligator representative")
		}

		// Encaps

		// Decaps
	}
}

// TestOkemCorrectness tests keypair generation for all KEMs.
func TestOkemCorrectness(t *testing.T)

// BenchmarkKeyGen tests keypair generation for all KEMs.
func BenchmarkKeyGen(t *testing.T)

// BenchmarkEncaps tests keypair generation for all KEMs.
func BenchmarkEncaps(t *testing.T)

// BenchmarkDecaps tests keypair generation for all KEMs.
func BenchmarkDecaps(t *testing.T)

// TODO this is only here for reference on how to do runtime-selection of benchmark inputs
func BenchmarkAppendFloat(b *testing.B) {
    benchmarks := []struct{
        name    string
        float   float64
        fmt     byte
        prec    int
        bitSize int
    }{
        {"Decimal", 33909, 'g', -1, 64},
        {"Float", 339.7784, 'g', -1, 64},
        {"Exp", -5.09e75, 'g', -1, 64},
        {"NegExp", -5.11e-95, 'g', -1, 64},
        {"Big", 123456789123456789123456789, 'g', -1, 64},
        ...
    }
    dst := make([]byte, 30)
    for _, bm := range benchmarks {
        b.Run(bm.name, func(b *testing.B) {
            for i := 0; i < b.N; i++ {
                AppendFloat(dst[:0], bm.float, bm.fmt, bm.prec, bm.bitSize)
            }
        })
    }
}